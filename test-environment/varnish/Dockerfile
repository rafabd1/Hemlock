# Use the official Varnish image
FROM varnish:6.6

# Copy the custom VCL file to the correct location in the container
COPY default.vcl /etc/varnish/default.vcl

# Expose the Varnish port
EXPOSE 80 