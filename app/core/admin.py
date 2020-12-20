from django.contrib import admin
from .models import User, Tag, Ingredient
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    ordering = ('-date_joined',)
    list_display = ('email', 'name', 'is_active', 'is_staff')
    list_filter = ('email', 'name', 'is_staff', 'is_superuser', 'is_active')
    search_fields = ('email', 'name')
    fieldsets = (
        (None, {'fields': ('email', 'password',)}),
        (_('Personal info'), {'fields': ('name',)}),
        (_('Permissions'), {
         'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
         }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'password1', 'password2')}
         ),
    )
    readonly_fields = ('id', 'date_joined', 'last_login')
    filter_horizontal = ('groups', 'user_permissions',)


class TagAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'user']

    class Meta:
        model = Tag


admin.site.register(Tag, TagAdmin)


class IngredientAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'user']

    class Meta:
        model = Ingredient


admin.site.register(Ingredient, IngredientAdmin)
