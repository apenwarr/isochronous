FROM buildpack-deps:stable as build

ADD . /opt/isochronous
WORKDIR /opt/isochronous
RUN make clean; make

FROM gcr.io/distroless/cc
COPY --from=build /opt/isochronous/isoping /
EXPOSE 4948/udp
CMD ["/isoping"]
