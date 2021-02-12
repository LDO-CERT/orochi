from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import RedirectView, DetailView

User = get_user_model()


class UserPluginView(LoginRequiredMixin, DetailView):
    queryset = User.objects.prefetch_related("plugins__plugin").all()
    slug_field = "username"
    slug_url_kwarg = "username"
    template_name = "users/user_plugins.html"


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
        return reverse("users:detail", kwargs={"username": self.request.user.username})


user_redirect_view = UserRedirectView.as_view()
