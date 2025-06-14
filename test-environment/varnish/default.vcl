# Varnish Configuration Language (VCL) file.
# This file defines how Varnish handles requests.

# VCL version 4.1
vcl 4.1;

import std;

# Define the backends (our vulnerable applications)
backend app_header_vuln {
    .host = "app-header-vuln";
    .port = "5001";
}

backend app_param_vuln {
    .host = "app-param-vuln";
    .port = "5002";
}

backend app_deception_vuln {
    .host = "app-deception-vuln";
    .port = "5003";
}

backend app_control {
    .host = "app-control";
    .port = "5004";
}

# Access Control List (ACL) for purging cache
acl purge {
    "localhost";
    "127.0.0.1";
}

sub vcl_recv {
    # Route requests to the correct backend based on the Host header
    if (req.http.host == "header-vuln.test") {
        set req.backend_hint = app_header_vuln;
    } elsif (req.http.host == "param-vuln.test") {
        set req.backend_hint = app_param_vuln;
    } elsif (req.http.host == "deception-vuln.test") {
        set req.backend_hint = app_deception_vuln;
    } else {
        set req.backend_hint = app_control; # Default to the control app
    }
    
    # Allow purging the cache
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(405, "Not allowed."));
        }
        return (purge);
    }

    # Don't cache POST requests
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # This is where the original mistake was. By unsetting the vulnerable header
    # here, it never reached the backend application. These headers should
    # be passed to the backend and only excluded from the cache key in vcl_hash.
    # I am removing the unset statements from this block.
    # A default VCL passes most headers, so no action is needed here.

    return (hash);
}

sub vcl_hash {
    # The default hash is based on URL and host. This is correct.
    # For parameter poisoning, we need to ensure the vulnerable parameter is NOT in the hash.
    if (req.url ~ "(\?|&)utm_source=") {
         set req.url = regsub(req.url, "(\?|&)utm_source=[^&]+", "");
         set req.url = regsub(req.url, "\\?&", "?");
    }

    hash_data(req.url);
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }

    # By default, Varnish does not hash X-Forwarded-Host, which is what we want.
    # No need to unset it here, we just need to ensure it's not explicitly added.
    return (lookup);
}

sub vcl_hit {
    # PURGE logic is now handled in vcl_recv and vcl_purge
    return (deliver);
}

sub vcl_miss {
    # PURGE logic is now handled in vcl_recv and vcl_purge
    return (fetch);
}

sub vcl_purge {
    # This subroutine is called when a PURGE request is processed.
    return (synth(200, "Purged"));
}

sub vcl_backend_response {
    # Set a TTL (Time To Live) for the cached object
    set beresp.ttl = 120s;
    set beresp.grace = 1h;

    # Add a header to see if the request was a cache HIT or MISS
    set beresp.http.X-Cache = "MISS";

    return (deliver);
}

sub vcl_deliver {
    # This happens right before the object is delivered to the client.
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
        set resp.http.X-Cache-Hits = obj.hits;
    } else {
        set resp.http.X-Cache = "MISS";
    }
    # Clean up Varnish-specific headers
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    # unset resp.http.Age; # Commented out for testing purposes - Hemlock relies on this.

    return (deliver);
} 