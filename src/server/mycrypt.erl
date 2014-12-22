-module(mycrypt).

-export([decrypt_frame_body/3, decrypt_shared_key/2, encrypt_frame_body/3, encrypt_shared_key/2]).

-import(log, [log/2, log/3]).

decrypt_frame_body(Data, 0, _SharedKey) ->
	Data;
decrypt_frame_body(Data, 1, _SharedKey) ->
	<<"FAKE_SIMPLE_CRYPT", Plain/binary>>=Data,
	Plain;
decrypt_frame_body(Data, 2, _SharedKey) ->
	<<"FAKE_BLOWFISH_CRYPT", Plain/binary>>=Data,
	Plain;
decrypt_frame_body(Data, Type, _SharedKey) ->
	log(log_debug, "Unsupported encrypt type: ~b\n", [Type]),
	Data.

encrypt_frame_body(Data, 0, _SharedKey) ->
	Data;
encrypt_frame_body(Data, 1, _SharedKey) ->
    <<"FAKE_SIMPLE_CRYPT", Data/binary>>;
encrypt_frame_body(Data, 2, _SharedKey) ->
    <<"FAKE_BLOWFISH_CRYPT", Data/binary>>;
encrypt_frame_body(Data, Type, _SharedKey) ->
    log(log_debug, "Unsupported encrypt type: ~b\n", [Type]),
    Data.

encrypt_shared_key(Data, _Pubkey) ->
	<<"FAKE_RSA_CRYPT", Data/binary>>.

decrypt_shared_key(<<"FAKE_RSA_CRYPT", Data/binary>>, _Privkey) ->
	Data.

