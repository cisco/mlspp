#include <doctest/doctest.h>
#include <hpke/random.h>
#include <mls/session.h>

using namespace mls;

class SessionTest
{
protected:
  const CipherSuite suite{ CipherSuite::ID::P256_AES128GCM_SHA256_P256 };
  const int group_size = 5;
  const size_t secret_size = 32;
  const bytes group_id = { 0, 1, 2, 3 };
  const bytes user_id = { 4, 5, 6, 7 };

  static const uint32_t no_except = 0xffffffff;

  std::vector<Session> sessions;

  HPKEPrivateKey new_init_key() { return HPKEPrivateKey::generate(suite); }

  SignaturePrivateKey new_identity_key()
  {
    return SignaturePrivateKey::generate(suite);
  }

  bytes fresh_secret() const { return random_bytes(secret_size); }

  void broadcast(const bytes& message) { broadcast(message, no_except); }

  void broadcast(const bytes& message, const uint32_t except)
  {
    for (auto& session : sessions) {
      if (except != no_except && session.index() == except) {
        continue;
      }

      session.handle(message);
    }
  }

  void broadcast_add()
  {
    const auto size = static_cast<uint32_t>(sessions.size());
    broadcast_add(size - 1, size);
  }

  void broadcast_add(uint32_t from, uint32_t index)
  {
    auto id_priv = new_identity_key();
    auto init_priv = new_init_key();
    auto cred = Credential::basic(user_id, id_priv.public_key);
    auto client = Client(suite, id_priv, cred, std::nullopt);

    // Initial add is different
    if (sessions.empty()) {
      auto creator = client.begin_session(group_id);
      sessions.emplace_back(std::move(creator));
      return;
    }

    auto initial_epoch = sessions[0].current_epoch();

    auto join = client.start_join();

    auto add = sessions[from].add(join.key_package());
    broadcast(add, index);

    auto [welcome, commit] = sessions[from].commit();
    broadcast(commit, index);

    auto next = join.complete(welcome);

    // Add-in-place vs. add-at-edge
    if (index == sessions.size()) {
      sessions.emplace_back(std::move(next));
    } else if (index < sessions.size()) {
      sessions[index] = std::move(next);
    } else {
      throw InvalidParameterError("Index too large for group");
    }

    check(initial_epoch);
  }

  void check(epoch_t initial_epoch) { check(initial_epoch, no_except); }

  void check(epoch_t initial_epoch, uint32_t except)
  {
    uint32_t ref = 0;
    if (except == 0 && sessions.size() > 1) {
      ref = 1;
    }

    auto label = std::string("test");
    auto context = bytes{ 4, 5, 6, 7 };
    auto size = 16;
    auto ref_export = sessions[ref].do_export(label, context, size);

    // Verify that everyone ended up in consistent states, and that
    // they can send and be received.
    for (auto& session : sessions) {
      if (except != no_except && session.index() == except) {
        continue;
      }

      REQUIRE(session == sessions[ref]);

      auto plaintext = bytes{ 0, 1, 2, 3 };
      auto encrypted = session.protect(plaintext);
      for (auto& other : sessions) {
        if (except != no_except && other.index() == except) {
          continue;
        }

        auto decrypted = other.unprotect(encrypted);
        REQUIRE(plaintext == decrypted);
      }

      REQUIRE(ref_export == session.do_export(label, context, size));
    }

    // Verify that the epoch got updated
    REQUIRE(sessions[ref].current_epoch() != initial_epoch);
  }
};

TEST_CASE_FIXTURE(SessionTest, "Two-Person Session Creation")
{
  broadcast_add();
}

TEST_CASE_FIXTURE(SessionTest, "Full-Size Session Creation")
{
  for (int i = 0; i < group_size - 1; i += 1) {
    broadcast_add();
  }
}

class RunningSessionTest : public SessionTest
{
protected:
  RunningSessionTest()
  {
    for (int i = 0; i < group_size; i += 1) {
      broadcast_add();
    }
  }
};

TEST_CASE_FIXTURE(RunningSessionTest, "Update within Session")
{
  for (int i = 0; i < group_size; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();

    auto update = sessions[i].update();
    broadcast(update);

    auto welcome_commit = sessions[i].commit();
    broadcast(std::get<1>(welcome_commit));

    check(initial_epoch);
  }
}

TEST_CASE_FIXTURE(RunningSessionTest, "Remove within Session")
{
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto evict_secret = fresh_secret();
    sessions.pop_back();

    auto remove = sessions[i - 1].remove(i);
    broadcast(remove);

    auto welcome_commit = sessions[i - 1].commit();
    broadcast(std::get<1>(welcome_commit));

    check(initial_epoch);
  }
}

TEST_CASE_FIXTURE(RunningSessionTest, "Replace within Session")
{
  for (int i = 0; i < group_size; ++i) {
    auto target = (i + 1) % group_size;

    // Remove target
    auto initial_epoch = sessions[i].current_epoch();
    auto remove = sessions[i].remove(target);
    broadcast(remove, target);
    auto welcome_commit = sessions[i].commit();
    broadcast(std::get<1>(welcome_commit), target);
    check(initial_epoch, target);

    // Re-add at target
    initial_epoch = sessions[i].current_epoch();
    broadcast_add(i, target);
    check(initial_epoch, target);
  }
}

TEST_CASE_FIXTURE(RunningSessionTest, "Full Session Life-Cycle")
{
  // 1. Group is created in the ctor

  // 2. Have everyone update
  for (int i = 0; i < group_size - 1; i += 1) {
    auto initial_epoch = sessions[0].current_epoch();
    auto update = sessions[i].update();
    broadcast(update);
    auto welcome_commit = sessions[i].commit();
    broadcast(std::get<1>(welcome_commit));
    check(initial_epoch);
  }

  // 3. Remove everyone but the creator
  for (int i = group_size - 1; i > 0; i -= 1) {
    auto initial_epoch = sessions[0].current_epoch();
    sessions.pop_back();
    auto remove = sessions[i - 1].remove(i);
    broadcast(remove);
    auto welcome_commit = sessions[i - 1].commit();
    broadcast(std::get<1>(welcome_commit));
    check(initial_epoch);
  }
}

TEST_CASE("Session with X509 Credential")
{
  // leaf_cert with p-256 public key
  const auto key_raw = from_hex(
    "f44068a9ca0f7e72135af0db88b342a692ab86dcc136589ecbf6943b5d5ada51");
  const auto leaf_der =
    from_hex("308202503082013802022457300d06092a864886f70d01010b05003042310b30"
             "09060355040613024d5631183016060355040a0c0f42696742726f7468657220"
             "496e632e3119301706035504030c10696e742e7763612e61636d652e636f6d30"
             "1e170d3139303630343038313033375a170d3230303630333038313033375a30"
             "42310b3009060355040613024d5631183016060355040a0c0f42696742726f74"
             "68657220496e632e3119301706035504030c1043452d453245452d4944454e54"
             "4954593059301306072a8648ce3d020106082a8648ce3d0301070342000489f0"
             "d7d8cf224436bd2d081b396c03f4bf1184085a4bf35525af1d42cebc4dcf9e8f"
             "95db20bcf366630ad16071a38aeb259ceddf16f9fb599ccb04c4de264e05a320"
             "301e300c0603551d130101ff04023000300e0603551d0f0101ff0404030205e0"
             "300d06092a864886f70d01010b05000382010100146d4f2b30c58ab43ef5c317"
             "40683d564fc01b7488df6eafc6090cf74ec542df3fb19f101927e931df3e0318"
             "7ecaeab2b62fda2c009dc6ebae020f1761c5e2f25b807c8e0fcce22b7bef6504"
             "a2edd202179b1974f4511585de82bdfd9da79a28b3d1a689fb09465e67d4e30d"
             "25e7a96032fa48e47a3ce48508083ea52850d4df04ac22583cb27e572526360e"
             "7ab13e2e313e74c136914f4d3229a6c344b982296a6960006ba37bd5644fa72f"
             "18872ce27f05655bcc61ffaf90eb623a1a5844f51a3c62ff5e9e232e5e50ec6a"
             "d89da3882088eac0036d9ed54ac5868bd640d08d764809cdfb490e0efd97ec39"
             "c64e6e2ddf69522c0533303b1856eea88ce942bf");
  const auto issuing_der =
    from_hex("30820259308201ff020223cf300a06082a8648ce3d040302303e310b30090603"
             "55040613024d5631183016060355040a0c0f42696742726f7468657220496e63"
             "2e3115301306035504030c0c7763612e61636d652e636f6d301e170d31393036"
             "30343038313033375a170d3230303630333038313033375a3042310b30090603"
             "55040613024d5631183016060355040a0c0f42696742726f7468657220496e63"
             "2e3119301706035504030c10696e742e7763612e61636d652e636f6d30820122"
             "300d06092a864886f70d01010105000382010f003082010a0282010100f1b334"
             "4af90b56902acff6df559eef84d3936308ee1adc626394bccb95ae67f17e0fef"
             "625c2c1fc39fadfd185da17085e0685f5019185d510bcd938460e7342a64daee"
             "1d4fc85d2ac2c79b445b454fd09a06cd68bd93f24937b68259e97bdf6b28d79a"
             "7867b89b7b85a9c00156030a1f867055ae628fc70604d780595986b4f3cabd87"
             "3d63927c9acd105d50f9850c0c55d694b91e202dc702cd0f237a57ddad173dc3"
             "aab4d2a8d043020e2ed68bf77f0d6707fb18d88951769ac321fa25cc33c78f53"
             "f2a49a59949fa78fda90713e27c33b774ddf48938bdae0ca90775610aa596a57"
             "5326258a74cee1cf787217fdf18d7e1b8e9ce5009ba995c38a35bf8923020301"
             "0001a3233021300f0603551d130101ff040530030101ff300e0603551d0f0101"
             "ff0404030201a6300a06082a8648ce3d040302034800304502203bf07cda259c"
             "29b54cb90455bbbce07dae4fe4096e5c493615fe967f29ef1997022100dcbc71"
             "d9865c93f3952abc7e671e625b8479214c1c9b62a7cc6a51a84a3610f4");

  std::vector<bytes> der_chain{ leaf_der, issuing_der };
  const mls::CipherSuite suite{
    mls::CipherSuite::ID::P256_AES128GCM_SHA256_P256
  };

  std::string alice_name = "alice";
  auto alice_id = bytes(alice_name.begin(), alice_name.end());

  mls::Credential alice_cred = mls::Credential::x509(der_chain);
  auto alice_sig_priv = mls::SignaturePrivateKey::parse(suite, key_raw);
  mls::KeyPackageOpts alice_opts_in;
  alice_opts_in.extensions.add(mls::KeyIDExtension{ alice_id });
  mls::Client alice_client(suite, alice_sig_priv, alice_cred, alice_opts_in);

  auto group_id = bytes{ 0, 1, 2, 3 };
  auto alice_session = alice_client.begin_session(group_id);

  std::string bob_name = "bob";
  auto bob_id = bytes(bob_name.begin(), bob_name.end());
  auto bob_sig_priv = mls::SignaturePrivateKey::generate(suite);
  auto bob_cred = mls::Credential::basic(bob_id, bob_sig_priv.public_key);
  mls::KeyPackageOpts bob_opts_in;
  bob_opts_in.extensions.add(mls::KeyIDExtension{ bob_id });

  mls::Client bob_client(suite, bob_sig_priv, bob_cred, bob_opts_in);

  auto bob_pending_join = bob_client.start_join();

  auto add = alice_session.add(bob_pending_join.key_package());
  auto [welcome, commit] = alice_session.commit(add);
  alice_session.handle(commit);

  auto bob_session = bob_pending_join.complete(welcome);

  REQUIRE(alice_session.authentication_secret() ==
          bob_session.authentication_secret());
}