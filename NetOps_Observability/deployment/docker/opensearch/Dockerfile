# Slim OpenSearch for the Correlix appliance (#install-bundle-size).
#
# The stock 2.16.0 image ships every OpenSearch plugin; this stack uses it
# purely as the log/flow SEARCH STORE (Vector indexes, the Go API queries DSL,
# the optional OSD add-on browses). The plugins removed below are ~560 MB of
# machinery nothing here calls — verified by repo-wide grep for their APIs
# (knn_vector, _plugins/_sql|_ppl|_ml|_anomaly, neural) before removal, and by
# a full stack boot + index/search/OSD check after.
#
# DELIBERATELY KEPT:
#   - opensearch-security (45 MB): disabled by env in compose, but the
#     documented prod-hardening path is "flip DISABLE_SECURITY_PLUGIN and add
#     certs" — removing the plugin would silently break that promise.
#   - index-management, job-scheduler, alerting, notifications*, observability,
#     reports-scheduler, asynchronous-search, geospatial, custom-codecs: small,
#     and some are dependency targets of each other / of OSD counterparts.
#
# Adding a feature that needs a removed plugin? Delete its line below — the
# base image is the pinned stock one, so the plugin comes back on rebuild.
FROM opensearchproject/opensearch:2.16.0@sha256:d5dd094fd48bdc4dfd032b7137c9c44a697071dcf320f1a76bc4159fe079679c AS trimmed

# Stage 1: trim. Each removal is its own && link so a failure (typo'd name,
# dependency refusal) fails the BUILD loudly instead of shipping half-trimmed.
# ORDER MATTERS: dependents before dependencies (skills extends ml — the
# plugin CLI refuses to remove an extended plugin first, exit 11).
RUN bin/opensearch-plugin remove opensearch-skills && \
    bin/opensearch-plugin remove opensearch-neural-search && \
    bin/opensearch-plugin remove opensearch-flow-framework && \
    bin/opensearch-plugin remove opensearch-anomaly-detection && \
    bin/opensearch-plugin remove opensearch-security-analytics && \
    bin/opensearch-plugin remove opensearch-ml && \
    bin/opensearch-plugin remove opensearch-knn && \
    bin/opensearch-plugin remove opensearch-sql && \
    bin/opensearch-plugin remove opensearch-performance-analyzer && \
    bin/opensearch-plugin remove opensearch-cross-cluster-replication && \
    rm -rf /usr/share/opensearch/performance-analyzer-rca

# Stage 2: FLATTEN. Deleting files in a Docker layer only writes whiteouts on
# top — `docker save` (the install bundle) still ships every base layer with
# the plugins in it, so the trim above saves ZERO bundle bytes on its own
# (measured: 920 MB before and after). Copying the trimmed filesystem into a
# fresh single-layer image is what actually drops the weight. COPY --from
# preserves ownership/permissions; the runtime config below reproduces the
# stock image's exactly (from docker inspect), minus the knn LD_LIBRARY_PATH
# whose plugin is gone.
FROM scratch
COPY --from=trimmed / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/share/opensearch/jdk/bin:/usr/share/opensearch/bin \
    JAVA_HOME=/usr/share/opensearch/jdk
USER 1000
WORKDIR /usr/share/opensearch
EXPOSE 9200 9300 9600 9650
ENTRYPOINT ["./opensearch-docker-entrypoint.sh"]
CMD ["opensearch"]
