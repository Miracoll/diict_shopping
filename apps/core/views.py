from django.shortcuts import render
from django.db import transaction
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication

from .models import Product, Cart, CartItem, Order, OrderItem
from .serializers import ProductSerializer, CartSerializer, OrderSerializer
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
def product_detail(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
    except Product.DoesNotExist:
        return Response({"error":"Product not found"}, status=status.HTTP_404_NOT_FOUND)
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

    try:
        cart = Cart.objects.get(user=user)
    except Cart.DoesNotExist:
        return Response({"error":"Cart is empty"}, status=status.HTTP_404_NOT_FOUND)

    cart_items = cart.items.all()
    if not cart_items.exists():
        return Response({"error":"Cart is empty"}, status=status.HTTP_404_NOT_FOUND)

    for item in cart_items:
        if int(item.product.stock) < int(item.quantity):
            return Response({"error":"insufficient stoct"}, status=status.HTTP_400_BAD_REQUEST)

    total_amount = cart.get_total()
    shipping_address = data["shipping_address"]
    phone_number = data["phone_number"]

    order = Order.objects.create(
        user=user,
        status="pending",
        phone_number = phone_number,
        shipping_address = shipping_address,
        total_amount = total_amount,
    )

    for item in cart_items:
        OrderItem.objects.create(
            order=order,
            product = item.product,
            quantity = item.quantity,
            price = item.product.price
        )
        item.product.stock -= int(item.quantity)
        item.product.save()

    # clear cart
    cart.items.all().delete()

    serializer = OrderSerializer(order)
    return Response(serializer.data, status=status.HTTP_201_CREATED)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def order_list(request):
    user = request.user

    orders = Order.objects.filter(user=user)
    serializer = OrderSerializer(orders, many=True)
    return Response(serializer.data)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def order_detail(request, order_id):
    try:
        order = Order.objects.get(id=order_id)
    except Order.DoesNotExist:
        return Response({"error":"Order not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = OrderSerializer(order)
    return Response(serializer.data)

