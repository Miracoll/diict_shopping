from django.urls import path
from . import views

urlpatterns = [
    path("product-list/", views.product_list),
    path("product/<int:product_id>/", views.product_detail),

    path("manage-cart/", views.manage_cart),
    path("delete-cart-item/<int:item_id>/", views.delete_cart_item),

    path("create-order/", views.create_order),
    path("order-list/", views.order_list),
    path("order/<int:order_id>/", views.order_detail),
]