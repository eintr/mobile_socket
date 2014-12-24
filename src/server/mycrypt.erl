-module(mycrypt).

-define(SHAREDKEY_BYTESIZE, 16).

-export([decrypt_frame_body/3, decrypt_shared_key/2, encrypt_frame_body/3, encrypt_shared_key/2]).
-export([rand_sharedkey/0, load_pubkey/1, load_privkey/1]).

-import(log, [log/2, log/3]).

load_pubkey(_Fname) ->
	<<"Fake_Pub_Key">>.

load_privkey(_Fname) ->
	<<"Fake_Priv_Key">>.

rand_sharedkey() ->
	crypto:rand_bytes(?SHAREDKEY_BYTESIZE).

decrypt_frame_body(Data, 0, _SharedKey) ->
	Data;
decrypt_frame_body(Data, 1, SharedKey) ->
	<<"FAKE_SIMPLE_CRYPT_KEY=", SharedKey:?SHAREDKEY_BYTESIZE/binary, Plain/binary>>=Data,
	zlib:unzip(Plain);
decrypt_frame_body(Data, 2, SharedKey) ->
	<<"FAKE_BLOWFISH_CRYPT_KEY=", SharedKey:?SHAREDKEY_BYTESIZE/binary, Plain/binary>>=Data,
	zlib:unzip(Plain);
decrypt_frame_body(Data, Type, _SharedKey) ->
	log(log_debug, "Unsupported encrypt type: ~b\n", [Type]),
	Data.

encrypt_frame_body(Data, 0, _SharedKey) ->
	Data;
encrypt_frame_body(Data, 1, SharedKey) ->
    <<"FAKE_SIMPLE_CRYPT_KEY=", SharedKey:?SHAREDKEY_BYTESIZE/binary, (zlib:zip(Data))/binary>>;
encrypt_frame_body(Data, 2, SharedKey) ->
    <<"FAKE_BLOWFISH_CRYPT_KEY=", SharedKey:?SHAREDKEY_BYTESIZE/binary, (zlib:zip(Data))/binary>>;
encrypt_frame_body(Data, Type, _SharedKey) ->
    log(log_debug, "Unsupported encrypt type: ~b\n", [Type]),
    Data.

encrypt_shared_key(Data, _Pubkey) ->
	<<"FAKE_RSA_CRYPT", Data/binary>>.

decrypt_shared_key(<<"FAKE_RSA_CRYPT", Data/binary>>, _Privkey) ->
	Data.

