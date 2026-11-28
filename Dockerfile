FROM rust:1-slim-bookworm@sha256:bb875b0f8ce726053e259034848c471840e96bfe591fd52556178ae9a05e6126 AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p plaintext-server && mkdir /data

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/plaintext-server /plaintext-server
COPY --from=build --chown=65532:65532 /data /data
ENV PLAINTEXT_DB=/data/plaintext.db PLAINTEXT_ADDR=0.0.0.0:8080
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/plaintext-server"]
