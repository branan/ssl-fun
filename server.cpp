#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace net = boost::asio;

int main() {
  // Create our boost::asio service and open a listen socket on port 9090
  net::io_service io_service;
  net::ip::tcp::acceptor acceptor(io_service, net::ip::tcp::endpoint(net::ip::tcp::v4(), 9090));

  // Create our SSL context, and set up our keys. Because we want to
  // use the fancy ECDHE-RSA-foo cipher, we need to also set up an
  // eliptic curve here. As long as you pick the same one on both
  // client and server you should be good. The last thing we do in
  // context setup is set the cipher we want to use.
  net::ssl::context ctx(net::ssl::context::tlsv12_server);
  ctx.use_certificate_file("../ca/localhost.crt", net::ssl::context::pem);
  ctx.use_private_key_file("../ca/localhost.key", net::ssl::context::pem);
  ctx.set_options(net::ssl::context::default_workarounds);
  EC_KEY *ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  SSL_CTX_set_tmp_ecdh (ctx.native_handle(), ecdh);
  EC_KEY_free (ecdh);
  SSL_CTX_set_cipher_list(ctx.native_handle(), "ECDHE-RSA-AES256-GCM-SHA384");

  // Here we create our actual socket, wait for the client, and then
  // do our SSL handshake. If we were doing real work with this app,
  // we would almost certainly be using async_accept, and would want
  // to kick off a new accept immediately so we can always get new
  // clients.
  net::ssl::stream<net::ip::tcp::socket> sock(io_service, ctx);
  acceptor.accept(sock.lowest_layer());
  sock.handshake(net::ssl::stream_base::server);
}
