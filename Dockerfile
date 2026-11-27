FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p plaintext-server && mkdir /data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/plaintext-server /plaintext-server
COPY --from=build --chown=65532:65532 /data /data
ENV PLAINTEXT_DB=/data/plaintext.db PLAINTEXT_ADDR=0.0.0.0:8080
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/plaintext-server"]
