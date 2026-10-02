import json
import logging
import uuid

from django.conf import settings
from django.shortcuts import render
from django.db import transaction
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication

from .models import Product, Cart, CartItem, Order, OrderItem
from .serializers import ProductSerializer, CartSerializer, OrderSerializer
from .services import PaystackError, PaystackService

logger = logging.getLogger(__name__)
# Create your views here.

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def product_list(request):
    if request.method == "GET":
        products = Product.objects.filter(is_active=True)
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)
    elif request.method == "POST":
        data = request.data
        user = request.user

        product =Product.objects.create(
            name=data["name"],
            description=data["description"],
            price=data["price"],
            stock=data["stock"],
            user=user,
            image=data.get("image", None),
        )
        serializer = ProductSerializer(product)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_product_list(request):
    products = Product.objects.filter(user=request.user, is_active=True)
    serializer = ProductSerializer(products, many=True)
    return Response(serializer.data)

@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsAuthenticated])
def product_detail(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
    except Product.DoesNotExist:
        return Response({"error":"Product not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = ProductSerializer(product)
        return Response(serializer.data)

    if product.user != request.user:
        return Response({"error":"Not allowed"}, status=status.HTTP_403_FORBIDDEN)

    if request.method == "PUT":
        data = request.data

        product.name = data.get("name", product.name)
        product.description = data.get("description", product.description)
        product.price = data.get("price", product.price)
        product.stock = data.get("stock", product.stock)
        product.image = data.get("image", product.image)
        product.save()

        serializer = ProductSerializer(product)
        return Response(serializer.data)

    elif request.method == "DELETE":
        product.delete()
        return Response({"message":"Product deleted"}, status=status.HTTP_204_NO_CONTENT)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def toggle_favorite(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
    except Product.DoesNotExist:
        return Response({"error":"Product not found"}, status=status.HTTP_404_NOT_FOUND)

    product.is_favorite = not product.is_favorite
    product.save()

    serializer = ProductSerializer(product)
    return Response(serializer.data)

@api_view(["GET", "POST", "DELETE"])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def manage_cart(request):
    user = request.user

    try:
        cart = Cart.objects.get(user=user)
    except Cart.DoesNotExist:
        cart = Cart.objects.create(user=user)

    if request.method == "POST":
        data = request.data
        product_id = data["product_id"]
        quantity = data["quantity"]

        product = Product.objects.get(id=product_id)

        if (int(quantity) > int(product.stock)):
            return Response({"error":"insufficient stoct"}, status=status.HTTP_400_BAD_REQUEST)

        cart_item, created = CartItem.objects.get_or_create(
            cart=cart, quantity=quantity, product=product
        )

        if not created:
            cart_item.quantity += quantity
            cart_item.save()

        serializer = CartSerializer(cart)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    elif request.method == "GET":
        serializer = CartSerializer(cart)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == "DELETE":
        cart.items.all().delete()
        return Response({"message":"Cart cleared"}, status=status.HTTP_204_NO_CONTENT)

@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def delete_cart_item(request, item_id):
    try:
        cart_item = CartItem.objects.get(id=item_id)
    except CartItem.DoesNotExist:
        return Response({"error":"No cart item found"}, status=status.HTTP_404_NOT_FOUND)
    if request.method == "DELETE":
        cart_item.delete()
        return Response({"message":"Cart cleared"}, status=status.HTTP_204_NO_CONTENT)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
@transaction.atomic
def create_order(request):
    user = request.user
    data = request.data
    cart = None

    # (product, quantity) pairs, taken from the request body when the app sends
    # its own cart, otherwise from the user's server cart.
    order_lines = []

    if data.get("items"):
        for item in data["items"]:
            try:
                product = Product.objects.select_for_update().get(id=item["product_id"], is_active=True)
            except Product.DoesNotExist:
                return Response({"error":"Product not found"}, status=status.HTTP_404_NOT_FOUND)

            quantity = int(item["quantity"])
            if quantity < 1:
                return Response({"error":"Invalid quantity"}, status=status.HTTP_400_BAD_REQUEST)

            order_lines.append((product, quantity))
    else:
        try:
            cart = Cart.objects.get(user=user)
        except Cart.DoesNotExist:
            return Response({"error":"Cart is empty"}, status=status.HTTP_404_NOT_FOUND)

        cart_items = cart.items.all()
        if not cart_items.exists():
            return Response({"error":"Cart is empty"}, status=status.HTTP_404_NOT_FOUND)

        for item in cart_items:
            order_lines.append((item.product, int(item.quantity)))

    for product, quantity in order_lines:
        if int(product.stock) < quantity:
            return Response({"error":f"insufficient stock for {product.name}"}, status=status.HTTP_400_BAD_REQUEST)

    total_amount = sum(product.price * quantity for product, quantity in order_lines)
    shipping_address = data["shipping_address"]
    phone_number = data["phone_number"]

    order = Order.objects.create(
        user=user,
        status="pending",
        phone_number = phone_number,
        shipping_address = shipping_address,
        total_amount = total_amount,
    )

    for product, quantity in order_lines:
        OrderItem.objects.create(
            order=order,
            product = product,
            quantity = quantity,
            price = product.price
        )
        product.stock -= quantity
        product.save()

    # clear cart
    if cart is not None:
        cart.items.all().delete()

    serializer = OrderSerializer(order)
    return Response(serializer.data, status=status.HTTP_201_CREATED)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def order_list(request):
    user = request.user

    orders = Order.objects.filter(user=user).order_by("-created_at")
    serializer = OrderSerializer(orders, many=True)
    return Response(serializer.data)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def order_detail(request, order_id):
    try:
        order = Order.objects.get(id=order_id, user=request.user)
    except Order.DoesNotExist:
        return Response({"error":"Order not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = OrderSerializer(order)
    return Response(serializer.data)


def _mark_order_paid(order_id, paystack_data):
    """Mark an order paid if Paystack's transaction data really covers it.

    Shared by the verify endpoint and the webhook, which can race each other
    for the same payment - the row lock makes the second one a no-op.
    Returns (order, paid).
    """
    with transaction.atomic():
        order = Order.objects.select_for_update().get(id=order_id)
        if order.status == "paid":
            return order, True

        if (
            paystack_data.get("status") != "success"
            or paystack_data.get("currency") != "NGN"
            or int(paystack_data.get("amount") or 0) != PaystackService.to_kobo(order.total_amount)
        ):
            return order, False

        order.status = "paid"
        order.paid_at = timezone.now()
        order.save(update_fields=["status", "paid_at", "updated_at"])
        return order, True

@api_view(["POST"])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def initialize_payment(request, order_id):
    try:
        order = Order.objects.get(id=order_id, user=request.user)
    except Order.DoesNotExist:
        return Response({"error":"Order not found"}, status=status.HTTP_404_NOT_FOUND)

    if order.status != "pending":
        return Response({"error":f"Order is already {order.status}"}, status=status.HTTP_400_BAD_REQUEST)

    # Paystack refuses a reference it has seen before, so every attempt gets a
    # fresh one; only the latest is kept on the order.
    reference = f"ORD-{order.id}-{uuid.uuid4().hex[:10]}"

    try:
        data = PaystackService.initialize_transaction(
            email=request.user.email,
            amount=order.total_amount,
            reference=reference,
            callback_url=settings.PAYSTACK_CALLBACK_URL,
            metadata={"order_id": order.id},
        )
    except PaystackError as exc:
        return Response({"error":str(exc)}, status=status.HTTP_502_BAD_GATEWAY)

    order.payment_reference = reference
    order.save(update_fields=["payment_reference", "updated_at"])

    return Response({
        "authorization_url": data.get("authorization_url"),
        "access_code": data.get("access_code"),
        "reference": reference,
    })

@api_view(["GET"])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def verify_payment(request, reference):
    try:
        order = Order.objects.get(payment_reference=reference, user=request.user)
    except Order.DoesNotExist:
        return Response({"error":"Order not found"}, status=status.HTTP_404_NOT_FOUND)

    if order.status != "paid":
        try:
            data = PaystackService.verify_transaction(reference)
        except PaystackError as exc:
            return Response({"error":str(exc)}, status=status.HTTP_502_BAD_GATEWAY)

        order, paid = _mark_order_paid(order.id, data)
        if not paid:
            return Response({"error":"Payment not successful"}, status=status.HTTP_400_BAD_REQUEST)

    serializer = OrderSerializer(order)
    return Response(serializer.data)

@api_view(["POST"])
@permission_classes([AllowAny])
@authentication_classes([])
def paystack_webhook(request):
    # The signature is over the exact bytes Paystack sent, so read the raw body
    # before DRF parses it.
    raw_body = request.body
    if not PaystackService.is_valid_signature(raw_body, request.headers.get("x-paystack-signature")):
        return Response({"error":"Invalid signature"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        event = json.loads(raw_body)
    except ValueError:
        return Response({"error":"Invalid payload"}, status=status.HTTP_400_BAD_REQUEST)

    if event.get("event") == "charge.success":
        data = event.get("data") or {}
        order = Order.objects.filter(payment_reference=data.get("reference")).first()
        if order is not None:
            _, paid = _mark_order_paid(order.id, data)
            if not paid:
                logger.warning("Webhook charge.success for %s did not match order %s", data.get("reference"), order.id)

    # Anything other than 200 makes Paystack retry, which only helps for
    # transient failures - not for events we've chosen to ignore.
    return Response(status=status.HTTP_200_OK)
