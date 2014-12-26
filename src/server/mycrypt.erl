-module(mycrypt).

-include_lib("public_key/include/public_key.hrl").

-define(SHAREDKEY_BYTESIZE, 16).
-define(BF_BLOCKSIZE, 8).
-define(BF_IVEC, <<"9obi1MYX">>).

-export([decrypt_frame_body/4, decrypt_shared_key/2, encrypt_frame_body/4, encrypt_shared_key/2]).
-export([rand_sharedkey/0, load_x509/1, extract_pubkey/1, load_privkey/1]).
-export([encrypt_algo1/2, decrypt_algo1/2]).

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

decrypt_frame_body(Data, 0, 0, _SharedKey) ->
	Data;
decrypt_frame_body(Data, 0, 1, _SharedKey) ->
	zlib:unzip(Data);
decrypt_frame_body(Data, 1, 0, SharedKey) ->
	decrypt_algo1(Data, SharedKey);
decrypt_frame_body(Data, 1, 1, SharedKey) ->
	zlib:unzip(decrypt_algo1(Data, SharedKey));
decrypt_frame_body(Data, Crypt, Zip, _SharedKey) ->
	log(log_debug, "Unsupported encrypt type: ~b,~b\n", [Crypt, Zip]),
	Data.

encrypt_frame_body(Data, 0, 0, _SharedKey) ->
	Data;
encrypt_frame_body(Data, 0, 1, _SharedKey) ->
	zlib:zip(Data);
encrypt_frame_body(Data, 1, 0, SharedKey) ->
	encrypt_algo1(Data, SharedKey);
encrypt_frame_body(Data, 1, 1, SharedKey) ->
	encrypt_algo1(zlib:zip(Data), SharedKey);
encrypt_frame_body(Data, Crypt, Zip, _SharedKey) ->
    log(log_debug, "Unsupported encrypt type: ~b,~b\n", [Crypt, Zip]),
    Data.

encrypt_shared_key(Data, Pubkey) ->
	public_key:encrypt_public(Data, Pubkey).

decrypt_shared_key(Data, Privkey) ->
	public_key:decrypt_private(Data, Privkey).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

encrypt_algo0(Data, _) ->
	Data.

encrypt_algo1(Data, Key) ->
	Padlen = padlen(byte_size(Data)),
	<<Padlen:8, (encrypt_algo1(<<Data/binary, 1415926535:(Padlen*8)/integer>>, Key, <<>>))/binary>>.

encrypt_algo1(<<>>, _Key, Res) -> Res;
encrypt_algo1(<<Block:?BF_BLOCKSIZE/binary, Rest/binary>>, Key, Res) ->
	encrypt_algo1(Rest, Key, <<Res/binary, (crypto:block_encrypt(blowfish_cbc, Key, ?BF_IVEC, Block))/binary>>).

decrypt_algo0(Data, _) ->
	Data.

decrypt_algo1(Data, Key) ->
	<<Padlen:8, Cipher/binary>> = Data,
	PayLoad_len = byte_size(Cipher)-Padlen,
	<<PayLoad:PayLoad_len/binary, _padding/binary>> = decrypt_algo1(Cipher, Key, <<>>),
	PayLoad.

decrypt_algo1(<<>>, _, Res) -> Res;
decrypt_algo1(<<Block:?BF_BLOCKSIZE/binary, Rest/binary>>, Key, Res) ->
	decrypt_algo1(Rest, Key, <<Res/binary, (crypto:block_decrypt(blowfish_cbc, Key, ?BF_IVEC, Block))/binary>>).

padlen(N) ->
	case (N rem ?BF_BLOCKSIZE) of
		0	->	0;
		Other	-> ?BF_BLOCKSIZE - Other
	end.

