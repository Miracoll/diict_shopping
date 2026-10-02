from django.urls import path
from . import views

urlpatterns = [
    path("product-list/", views.product_list),
    path("user-product-list/", views.user_product_list),
    path("product/<int:product_id>/", views.product_detail),
    path("toggle-favorite/<int:product_id>/", views.toggle_favorite),

    path("manage-cart/", views.manage_cart),
    path("delete-cart-item/<int:item_id>/", views.delete_cart_item),

    path("create-order/", views.create_order),
    path("order-list/", views.order_list),
    path("order/<int:order_id>/", views.order_detail),
    path("order/<int:order_id>/pay/", views.initialize_payment),

    path("payment/verify/<str:reference>/", views.verify_payment),
    path("payment/webhook/", views.paystack_webhook),
]