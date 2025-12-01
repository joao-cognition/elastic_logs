# Sample Dockerfile with common issues for Devin to analyze
# This Dockerfile intentionally contains some anti-patterns and security issues
# for demonstration purposes

FROM ubuntu:latest

# Issue: Running as root (security concern)
# Issue: Using 'latest' tag (reproducibility concern)

# Issue: Multiple RUN commands that could be combined
RUN apt-get update
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
RUN apt-get install -y curl
RUN apt-get install -y wget

# Issue: Not cleaning up apt cache
# Issue: Installing unnecessary packages

# Issue: Hardcoded secrets (security vulnerability)
# DEMO: These are intentionally fake placeholder values to demonstrate the anti-pattern
ENV DATABASE_PASSWORD=REPLACE_WITH_SECRET_DO_NOT_HARDCODE
ENV API_KEY=REPLACE_WITH_API_KEY_DO_NOT_HARDCODE

# Issue: Exposing sensitive port without documentation
EXPOSE 22
EXPOSE 3306
EXPOSE 5432

# Issue: Using ADD instead of COPY for local files
ADD ./app /app
ADD ./config /config

# Issue: Not setting a non-root user
WORKDIR /app

# Issue: Using shell form instead of exec form
CMD python3 app.py

# Issue: No health check defined
# Issue: No .dockerignore mentioned
# Issue: Large base image instead of slim/alpine variant
