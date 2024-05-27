from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, ProfilePicModel, FamilyDetailModel, WorkInformationModel,
    DocumentsModel, Payment, Application
)


class ProfilePicInline(admin.StackedInline):
    model = ProfilePicModel
    can_delete = False
    verbose_name = 'Profile picture'


class FamilyDetailInline(admin.StackedInline):
    model = FamilyDetailModel
    can_delete = False
    verbose_name = 'Family Detail'


class WorkInformationInline(admin.StackedInline):
    model = WorkInformationModel
    can_delete = False
    verbose_name = 'Work Permit Information'


class DocumentsInline(admin.StackedInline):
    model = DocumentsModel
    can_delete = False
    verbose_name = 'Documents'


class PaymentsInline(admin.StackedInline):
    model = Payment
    can_delete = False
    verbose_name = 'Payments'


class ApplicationInline(admin.StackedInline):
    model = Application
    can_delete = False
    verbose_name = 'Application'


class UserModelAdmin(BaseUserAdmin):
    list_display = ['id', 'email', 'name', 'date_of_birth', 'gender', 'address', 'contact', 'is_admin']
    list_filter = ['is_admin']
    fieldsets = [
        ('User Credentials', {'fields': ['email', 'password']}),
        ('Personal Information', {'fields': ['name', 'date_of_birth', 'gender', 'address', 'contact', ]}),
        ('Permissions', {'fields': ['is_admin']}),
    ]

    add_fieldsets = [
        (
            None,
            {
                'classes': ['wide'],
                'fields': ['email', 'name', 'date_of_birth', 'gender', 'address', 'contact', 'password1', 'password2'],
            },
        ),
    ]

    search_fields = ['email']
    ordering = ['email', 'id']
    filter_horizontal = []
    inlines = (ProfilePicInline, FamilyDetailInline, WorkInformationInline, DocumentsInline, PaymentsInline, ApplicationInline)


admin.site.register(User, UserModelAdmin)

@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ['application_status', 'date_of_submission']

@admin.register(WorkInformationModel)
class WorkInformationAdmin(admin.ModelAdmin):
    list_display = ['user']

@admin.register(DocumentsModel)
class DocumentsAdmin(admin.ModelAdmin):
    list_display = ['user']


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['user', 'pidx', 'total_amount', 'purchase_order_id', 'purchase_order_name', 'status', 'created_at']
