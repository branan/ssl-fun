#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>

using namespace std;

namespace net = boost::asio;

bool validate_hostname(const char* hostname, X509* cert) {
  // All of this pulls the CN field from the cert, so we can compare
  // it against the hostname we are trying to connect to.
  X509_NAME* subject_name = X509_get_subject_name(cert);
  int common_name_loc = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
  X509_NAME_ENTRY* common_name_entry = X509_NAME_get_entry(subject_name, common_name_loc);
  ASN1_STRING* common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
  char* common_name = (char*)ASN1_STRING_data(common_name_asn1);
  return strcasecmp(hostname, common_name) == 0;
}

int main() {
  // This first chunk is boost::asio boilerplate - we set things up to
  // talk to localhost on port 9090
  net::io_service io_service;
  net::ip::tcp::resolver resolver(io_service);
  net::ip::tcp::resolver::query query("localhost", "9090");
  net::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
  net::ip::tcp::endpoint endpoint;
  bool found_endpoint = false;

  // We could end up with an ipv6 endpoint from the resolver, but our
  // example server code doesn't support ipv6. We just have to flip
  // through the results until we find ipv4.
  while(iterator != net::ip::tcp::resolver::iterator()) {
    endpoint = *iterator++;
    if(endpoint.protocol() == net::ip::tcp::v4()) {
      found_endpoint = true;
      break;
    }
  }

  if(!found_endpoint) {
    cout << "Could not resolve ipv4 DNS for localhost... WTF?" << endl;
    return 1;
  }

  // Now we set up the SSL context, including loading the CA cert.
  // We don't need to setup any EC params - that's all handled
  // server-side.  We also set our preferred chipher while we're here
  net::ssl::context ctx(net::ssl::context::tlsv12_client);
  ctx.load_verify_file("../ca/rootCA.pem");
  ctx.set_options(net::ssl::context::default_workarounds);
  SSL_CTX_set_cipher_list(ctx.native_handle(), "ECDHE-RSA-AES256-GCM-SHA384");

  // Create our socket, connect to the server, and do our SSL
  // handshake. We'll get an exception here if the server cert isn't
  // signed by our CA.
  net::ssl::stream<net::ip::tcp::socket> sock(io_service, ctx);
  sock.set_verify_mode(net::ssl::verify_peer);
  sock.lowest_layer().connect(endpoint);
  sock.handshake(net::ssl::stream_base::client);

  // Now that we've finished the handshake, we want to validate that
  // we've connected not just to any old trusted server, but the
  // trusted server we intended to. We grab the server's cert from the
  // SSL session and verify the hostname matches the one we wanted
  X509* server_cert = SSL_get_peer_certificate(sock.native_handle());
  if(!validate_hostname("localhost", server_cert))
    cout << "Hostname mismatch!";

  cout << "Using: " << SSL_get_cipher_name(sock.native_handle()) << endl;
}
