

def get_uri_path_segment_param_value(request, param_name):
    """
    :type request: WSGIRequest
    :type param_name: String
    """

    if not isinstance(wsgi_request, HttpWSGIRequest):
        return None

    uri = request.request_uri

    if uri is None:
        return None

    try:
        # try to get rid of the query string
        uri = uri[:uri.index('?')]
    except ValueError:
        pass

    try:
        index = uri.index(';')
    except ValueError:
        # no path segment params - return
        return None

    # there are path segment params, so let's get the last one that
    # may exist:

    # uri now contains only the path segment params
    uri = uri[(index + 1):]

    token = param_name + "="
    # we only care about the last param (SESSIONID):
    index = uri.rfind(token)
    if (index < 0):
        # no segment param:
        return None

    uri = uri[index + len(token):]

    try:
        # strip off any remaining segment params:
        index = uri.index(';')
        uri = uri[0:index]
    except:
        pass

    # what remains is the value:
    return uri
