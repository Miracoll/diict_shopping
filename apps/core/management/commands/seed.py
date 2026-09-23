import random
from datetime import timedelta
from decimal import Decimal

from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from apps.core.models import Cart, CartItem, Order, OrderItem, Product
from apps.user.models import User

FIRST_NAMES = [
    "Chinedu", "Amaka", "Tunde", "Ngozi", "Emeka", "Funke", "Ifeanyi", "Zainab",
    "David", "Sarah", "Michael", "Grace", "Daniel", "Blessing", "John", "Mary",
    "Samuel", "Joy", "Peter", "Esther", "James", "Ruth", "Paul", "Chioma",
]
LAST_NAMES = [
    "Okafor", "Adeyemi", "Obi", "Balogun", "Eze", "Ibrahim", "Nwosu", "Okonkwo",
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
]
CITIES = ["Lagos", "Abuja", "Enugu", "Port Harcourt", "Ibadan", "Kano", "Onitsha", "Owerri"]
STREETS = ["Allen Avenue", "Awolowo Road", "Ogui Road", "Aba Road", "Ring Road", "Adeola Odeku"]

ADJECTIVES = ["Classic", "Premium", "Smart", "Wireless", "Vintage", "Eco", "Pro", "Ultra", "Mini", "Deluxe"]
PRODUCTS = {
    "Headphones": (50, 400), "Sneakers": (40, 250), "Backpack": (25, 150),
    "Watch": (60, 900), "T-Shirt": (10, 45), "Jacket": (50, 300),
    "Laptop Stand": (20, 90), "Keyboard": (30, 200), "Mouse": (15, 120),
    "Water Bottle": (8, 40), "Sunglasses": (20, 250), "Desk Lamp": (18, 110),
    "Phone Case": (8, 50), "Speaker": (35, 350), "Coffee Mug": (6, 30),
    "Jeans": (30, 150), "Handbag": (40, 600), "Blender": (35, 220),
    "Perfume": (25, 280), "Power Bank": (18, 90),
}

STATUSES = [s for s, _ in Order.STATUS_CHOICE]


def phone():
    return "+234" + random.choice("789") + random.choice("01") + "".join(random.choices("0123456789", k=8))


def address():
    return f"{random.randint(1, 250)} {random.choice(STREETS)}, {random.choice(CITIES)}, Nigeria"


class Command(BaseCommand):
    help = "Populate the database with fake users, products, carts and orders."

    def add_arguments(self, parser):
        parser.add_argument("--users", type=int, default=50)
        parser.add_argument("--products", type=int, default=200)
        parser.add_argument("--orders", type=int, default=500)
        parser.add_argument("--clear", action="store_true", help="Delete existing seeded data first (keeps superusers).")

    @transaction.atomic
    def handle(self, *args, **opts):
        if opts["clear"]:
            User.objects.filter(is_superuser=False, username__startswith="seed_").delete()
            self.stdout.write("Cleared previously seeded users and their data.")

        password = make_password("password123")
        start = User.objects.filter(username__startswith="seed_").count()
        users = []
        for i in range(start, start + opts["users"]):
            first, last = random.choice(FIRST_NAMES), random.choice(LAST_NAMES)
            users.append(User(
                username=f"seed_{first.lower()}{i}",
                email=f"{first.lower()}.{last.lower()}{i}@example.com",
                first_name=first,
                last_name=last,
                password=password,
                phone_number=phone(),
                gender=random.choice(["male", "female", None]),
            ))
        users = User.objects.bulk_create(users)

        products = []
        for _ in range(opts["products"]):
            kind = random.choice(list(PRODUCTS))
            low, high = PRODUCTS[kind]
            name = f"{random.choice(ADJECTIVES)} {kind}"[:30]
            products.append(Product(
                name=name,
                description=f"{name} — quality {kind.lower()} built to last. Great value for everyday use.",
                price=Decimal(random.randint(low * 100, high * 100)) / 100,
                stock=random.randint(0, 500),
                is_active=random.random() > 0.1,
                user=random.choice(users),
                image=f"https://picsum.photos/seed/{random.randint(1, 100000)}/600/600",
            ))
        products = Product.objects.bulk_create(products)

        # Carts for ~70% of users (Cart is one-to-one with User)
        carts = Cart.objects.bulk_create([Cart(user=u) for u in users if random.random() < 0.7])
        cart_items = []
        for cart in carts:
            for product in random.sample(products, k=random.randint(1, 5)):
                cart_items.append(CartItem(cart=cart, product=product, quantity=random.randint(1, 4)))
        CartItem.objects.bulk_create(cart_items)

        now = timezone.now()
        order_count = item_count = 0
        for _ in range(opts["orders"]):
            chosen = random.sample(products, k=random.randint(1, 6))
            lines = [(p, random.randint(1, 5)) for p in chosen]
            total = sum(p.price * q for p, q in lines)
            status = random.choice(STATUSES)
            order = Order.objects.create(
                user=random.choice(users),
                status=status,
                total_amount=total,
                shipping_address=address(),
                phone_number=phone(),
            )
            # auto_now_add ignores passed values, so backdate with update()
            created = now - timedelta(days=random.randint(0, 365), minutes=random.randint(0, 1440))
            paid = created + timedelta(minutes=random.randint(1, 120)) if status not in ("pending", "cancelled") else None
            Order.objects.filter(pk=order.pk).update(created_at=created, paid_at=paid)
            OrderItem.objects.bulk_create([
                OrderItem(order=order, product=p, quantity=q, price=p.price) for p, q in lines
            ])
            order_count += 1
            item_count += len(lines)

        self.stdout.write(self.style.SUCCESS(
            f"Created {len(users)} users, {len(products)} products, {len(carts)} carts "
            f"({len(cart_items)} items), {order_count} orders ({item_count} items). "
            f"Seeded user password: password123"
        ))
