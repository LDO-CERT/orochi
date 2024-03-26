from typing import Any

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models.query import QuerySet
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import DetailView, RedirectView

from orochi.website.models import UserPlugin

User = get_user_model()


class UserYaraView(LoginRequiredMixin, DetailView):
    queryset = User.objects.prefetch_related("rules").all()
    slug_field = "username"
    slug_url_kwarg = "username"
    template_name = "users/user_rules.html"

    def get_queryset(self) -> QuerySet[Any]:
        mine = self.request.user == User.objects.get(username=self.kwargs["username"])
        qs = super().get_queryset()
        if mine:
            return qs
        return qs.none()


user_yara_view = UserYaraView.as_view()


class UserPluginView(LoginRequiredMixin, DetailView):
    queryset = User.objects.prefetch_related("plugins__plugin").all()
    slug_field = "username"
    slug_url_kwarg = "username"
    template_name = "users/user_plugins.html"

    def post(self, request, *args, **kwargs):
        action = request.POST.get("action")
        plugin_ids = request.POST.getlist("id[]")
        for plugin in plugin_ids:
            up = get_object_or_404(UserPlugin, pk=plugin, user=request.user)
            up.automatic = bool(action == "enable")
            up.save()
        self.object = self.get_object()
        context = self.get_context_data(object=self.object)
        messages.add_message(
            request,
            messages.SUCCESS if action == "enable" else messages.ERROR,
            "{} plugins {}d".format(len(plugin_ids), action),
        )
        return self.render_to_response(context)

    def get_queryset(self) -> QuerySet[Any]:
        mine = self.request.user == User.objects.get(username=self.kwargs["username"])
        qs = super().get_queryset()
        if mine:
            return qs
        return qs.none()


user_plugins_view = UserPluginView.as_view()


class UserBookmarksView(LoginRequiredMixin, DetailView):
    queryset = User.objects.prefetch_related("bookmarks").all()
    slug_field = "username"
    slug_url_kwarg = "username"
    template_name = "users/user_bookmarks.html"

    def get_queryset(self) -> QuerySet[Any]:
        mine = self.request.user == User.objects.get(username=self.kwargs["username"])
        qs = super().get_queryset()
        if mine:
            return qs
        return qs.none()


user_bookmarks_view = UserBookmarksView.as_view()


class UserRedirectView(LoginRequiredMixin, RedirectView):
    permanent = False

    def get_redirect_url(self, *args, **kwargs):
        return reverse(
            "users:bookmarks", kwargs={"username": self.request.user.username}
        )


user_redirect_view = UserRedirectView.as_view()
