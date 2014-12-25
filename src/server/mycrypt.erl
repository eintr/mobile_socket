-module(mycrypt).

-include_lib("public_key/include/public_key.hrl").

-define(SHAREDKEY_BYTESIZE, 16).
-define(BF_BLOCKSIZE, 8).
-define(BF_IVEC, <<"9obi1MYX">>).

-export([decrypt_frame_body/3, decrypt_shared_key/2, encrypt_frame_body/3, encrypt_shared_key/2]).
-export([rand_sharedkey/0, load_x509/1, extract_pubkey/1, load_privkey/1]).
-export([encrypt_algo2/2, decrypt_algo2/2]).

-import(log, [log/2, log/3]).

% FIXME: load_x509(Fname) and extract_pubkey(CertBin) is ugly, fix it.
load_x509(Fname) ->
	{ok, PemBin} = file:read_file(Fname),
	[{'Certificate', Cert, not_encrypted}] = public_key:pem_decode(PemBin),
	{ok, Cert}.
extract_pubkey(CertBin) ->
	CertRec = public_key:pkix_decode_cert(CertBin, otp),
	((CertRec#'OTPCertificate'.tbsCertificate)#'OTPTBSCertificate'.subjectPublicKeyInfo)#'OTPSubjectPublicKeyInfo'.subjectPublicKey.
	
load_privkey(Fname) ->
	{ok, PemBin} = file:read_file(Fname),
	[RSAEntry] = public_key:pem_decode(PemBin),
	{ok, public_key:pem_entry_decode(RSAEntry)}.

rand_sharedkey() ->
	crypto:rand_bytes(?SHAREDKEY_BYTESIZE).

decrypt_frame_body(Data, 0, _SharedKey) ->
	Data;
decrypt_frame_body(Data, 1, _SharedKey) ->
	<<"FAKE_SIMPLE_CRYPT", Plain/binary>>=Data,
	zlib:unzip(Plain);
decrypt_frame_body(Data, 2, SharedKey) ->
	%<<"FAKE_BLOWFISH_CRYPT_KEY=", SharedKey:?SHAREDKEY_BYTESIZE/binary, Plain/binary>>=Data,
	%zlib:unzip(Plain);
	zlib:unzip(decrypt_algo2(Data, SharedKey));
decrypt_frame_body(Data, Type, _SharedKey) ->
	log(log_debug, "Unsupported encrypt type: ~b\n", [Type]),
	Data.

encrypt_frame_body(Data, 0, _SharedKey) ->
	Data;
encrypt_frame_body(Data, 1, _SharedKey) ->
    <<"FAKE_SIMPLE_CRYPT", (zlib:zip(Data))/binary>>;
encrypt_frame_body(Data, 2, SharedKey) ->
    %<<"FAKE_BLOWFISH_CRYPT_KEY=", SharedKey:?SHAREDKEY_BYTESIZE/binary, (zlib:zip(Data))/binary>>;
	encrypt_algo2(zlib:zip(Data), SharedKey);
encrypt_frame_body(Data, Type, _SharedKey) ->
    log(log_debug, "Unsupported encrypt type: ~b\n", [Type]),
    Data.

encrypt_shared_key(Data, Pubkey) ->
	public_key:encrypt_public(Data, Pubkey).

decrypt_shared_key(Data, Privkey) ->
	public_key:decrypt_private(Data, Privkey).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

encrypt_algo2(Data, Key) ->
	Padlen = padlen(byte_size(Data)),
	<<Padlen:8, (encrypt_algo2(<<Data/binary, 1415926535:(Padlen*8)/integer>>, Key, <<>>))/binary>>.

encrypt_algo2(<<>>, _Key, Res) -> Res;
encrypt_algo2(<<Block:?BF_BLOCKSIZE/binary, Rest/binary>>, Key, Res) ->
	encrypt_algo2(Rest, Key, <<Res/binary, (crypto:block_encrypt(blowfish_cbc, Key, ?BF_IVEC, Block))/binary>>).

decrypt_algo2(Data, Key) ->
	<<Padlen:8, Cipher/binary>> = Data,
	PayLoad_len = byte_size(Cipher)-Padlen,
	<<PayLoad:PayLoad_len/binary, _padding/binary>> = decrypt_algo2(Cipher, Key, <<>>),
	PayLoad.

decrypt_algo2(<<>>, _, Res) -> Res;
decrypt_algo2(<<Block:?BF_BLOCKSIZE/binary, Rest/binary>>, Key, Res) ->
	decrypt_algo2(Rest, Key, <<Res/binary, (crypto:block_decrypt(blowfish_cbc, Key, ?BF_IVEC, Block))/binary>>).

padlen(N) ->
	case (N rem ?BF_BLOCKSIZE) of
		0	->	0;
		Other	-> ?BF_BLOCKSIZE - Other
	end.

