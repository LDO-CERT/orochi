from orochi.website.models import UserPlugin
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import RedirectView, DetailView
from django.shortcuts import get_object_or_404
from django.contrib import messages

User = get_user_model()


class UserYaraView(LoginRequiredMixin, DetailView):
    queryset = User.objects.prefetch_related("rules").all()
    slug_field = "username"
    slug_url_kwarg = "username"
    template_name = "users/user_rules.html"


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
            up.automatic = True if action == "enable" else False
            up.save()
        self.object = self.get_object()
        context = self.get_context_data(object=self.object)
        messages.add_message(
            request,
            messages.SUCCESS if action == "enable" else messages.ERROR,
            "{} plugins {}d".format(len(plugin_ids), action),
        )
        return self.render_to_response(context)


user_plugins_view = UserPluginView.as_view()


class UserBookmarksView(LoginRequiredMixin, DetailView):
    queryset = User.objects.prefetch_related("bookmarks").all()
    slug_field = "username"
    slug_url_kwarg = "username"
    template_name = "users/user_bookmarks.html"


user_bookmarks_view = UserBookmarksView.as_view()


class UserRedirectView(LoginRequiredMixin, RedirectView):
    permanent = False

    def get_redirect_url(self):
        return reverse(
            "users:bookmarks", kwargs={"username": self.request.user.username}
        )


user_redirect_view = UserRedirectView.as_view()
