#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>

using namespace std;

namespace net = boost::asio;

bool validate_hostname(const char* hostname, X509* cert) {
  X509_NAME* subject_name = X509_get_subject_name(cert);
  int common_name_loc = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
  X509_NAME_ENTRY* common_name_entry = X509_NAME_get_entry(subject_name, common_name_loc);
  ASN1_STRING* common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
  char* common_name = (char*)ASN1_STRING_data(common_name_asn1);
  return strcasecmp(hostname, common_name) == 0;
}

int main() {
  net::io_service io_service;
  net::ip::tcp::resolver resolver(io_service);
  net::ip::tcp::resolver::query query("127.0.0.1", "9090");
  net::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
  net::ip::tcp::endpoint endpoint = *iterator;

  net::ssl::context ctx(net::ssl::context::tlsv12_client);
  ctx.load_verify_file("../ca/rootCA.pem");
  ctx.set_options(net::ssl::context::default_workarounds);
  EC_KEY *ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  SSL_CTX_set_tmp_ecdh (ctx.native_handle(), ecdh);
  EC_KEY_free (ecdh);
  SSL_CTX_set_cipher_list(ctx.native_handle(), "ECDHE-RSA-AES256-GCM-SHA384");

  net::ssl::stream<net::ip::tcp::socket> sock(io_service, ctx);
  sock.set_verify_mode(net::ssl::verify_peer);
  sock.lowest_layer().connect(endpoint);
  sock.handshake(net::ssl::stream_base::client);

  X509* server_cert = SSL_get_peer_certificate(sock.native_handle());
  // From here on out we're dealing with C objects. Aren't you excited?
  if(!validate_hostname("localhost", server_cert))
    cout << "Hostname mismatch!";

  cout << "Using: " << SSL_get_cipher_name(sock.native_handle()) << endl;
}
