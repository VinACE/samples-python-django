from django.conf import settings
import pystache


def get_partial(name):
    # Helper method to return partial from file system
    pystache_render = pystache.Renderer(search_dirs=settings.TEMPLATES_DIR)
    partials = {
        'doc': pystache_render.load_template(name)
    }
    return pystache.Renderer(search_dirs=settings.TEMPLATES_DIR,
                             partials=partials)
