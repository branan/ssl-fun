#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace net = boost::asio;

int main() {
  net::io_service io_service;
  net::ip::tcp::acceptor acceptor(io_service, net::ip::tcp::endpoint(net::ip::tcp::v4(), 9090));

  net::ssl::context ctx(net::ssl::context::tlsv12_server);
  ctx.use_certificate_file("../ca/localhost.crt", net::ssl::context::pem);
  ctx.use_private_key_file("../ca/localhost.key", net::ssl::context::pem);
  ctx.set_options(net::ssl::context::default_workarounds);
  EC_KEY *ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  SSL_CTX_set_tmp_ecdh (ctx.native_handle(), ecdh);
  EC_KEY_free (ecdh);
  SSL_CTX_set_cipher_list(ctx.native_handle(), "ECDHE-RSA-AES256-GCM-SHA384");

  net::ssl::stream<net::ip::tcp::socket> sock(io_service, ctx);
  acceptor.accept(sock.lowest_layer());
  sock.handshake(net::ssl::stream_base::server);
}
