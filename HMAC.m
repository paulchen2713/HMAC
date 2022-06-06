%
% HMAC based on SHA-224, SHA-512
%
clear;
clc;
%
ipad = '36';
opad = '5c';
% HMAC_SHA3-224
% HASH_type = 'SHA3-224';
% HASH_len = 224;
% B = 144; % Block length = 144
% Key length = 28
% Tag length = 28
%
%
% sample 1
%
% MAC_length = 28;
% input_data = 'Sample message for keylen<blocklen';
% key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b';
%
%
% sample 2
%
% MAC_length = 28;
% input_data = 'Sample message for keylen=blocklen';
% key1 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849';
% key2 = '4a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f';
% key = strcat(key1,key2);
%
% sample 3
%
% MAC_length = 28;
% inputdata = 'Sample message for keylen>blocklen';
% key1 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
% key2 = '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f';
% key3 = '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab';
% key = strcat(key1,key2);
% key = strcat(key,key3);
%
% sample 4
%
% MAC_length = 14;
% input_data = 'Sample message for keylen<blocklen, with truncated tag';
% key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b';
%
%
% HMAC_SHA3-512
HASH_type = 'SHA3-512';
HASH_len = 512;
B = 72; % Block length = 144
% Key length = 64
% Tag length = 64
%
%
% HMAC_SHA3-512 sample 1
%
MAC_len = 64;
input_data = 'Sample message for keylen<blocklen';
key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
%
%
% HMAC_SHA3-512 sample 2
%
% MAC_length=64;
% inputdata='Sample message for keylen=blocklen';
% key='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647';
%
% HMAC_SHA3-512 sample 3
%
% MAC_length=64;
% inputdata='Sample message for keylen>blocklen';
% key1='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
% key2='404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687';
% key=strcat(key1,key2);
%
% HMAC_SHA3-512 sample 4
%
% MAC_length=32;
% inputdata='Sample message for keylen<blocklen, with truncated tag';
% key='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
%
%
input_len = length(input_data);
text = char();
for i = 1 : input_len
    text = strcat(text, dec2hex(double(input_data(i)), 2));
end
text = lower(text);
%
fprintf('\n Block length = %d\n', B);
fprintf('\n Key length = %d\n', length(key)/2);
fprintf('\n Tag length = %d\n', MAC_len);
fprintf('\n Input data in char is: %s\n', input_data);
fprintf('\n Text is: %s\n', text);
fprintf('\n Input data in hex is: %s \n', key);
%
% key preprocessing, step 1~3: Determine K0
%
key_len = length(key) / 2;
if key_len < B
    % step 2
    K0 = key;
    for i = 1 : B - key_len
        K0 = strcat(K0, '00');
    end
elseif key_len == B
    % step 1
    K0 = key;
elseif key_len > B
    % step 3
    K0 = SHA3_text(K0, HASH_type, HASH_len);
    for i = 1 : B - HASH_len/8
        K0 = strcat(K0, '00');
    end
end
fprintf('\n K0 is: %s \n', K0);
%
% K0 XOR, step 4: K0 XOR ipad
%
ipad8 = uint8(hex2dec(ipad));
K0_ipad = K0;
for i = 1 : B
    % result of step 4
    K0_step4_dec = bitxor(uint8(hex2dec(K0_ipad((i - 1) * 2 + 1 : i*2))), ipad8);
    K0_ipad((i - 1) * 2 + 1 : i*2) = dec2hex(K0_step4_dec, 2);
end
K0_ipad = lower(K0_ipad);
fprintf('\n K0 XOR ipad is: %s \n', K0_ipad);
%
%
%
K0_ipad_text = strcat(K0_ipad, text);
K0_ipad_text_HASH = SHA3_hex(K0_ipad_text, HASH_type, HASH_len);
fprintf('\n HASH((K0 XOR ipad) || text) is: %s \n', K0_ipad_text_HASH);
%
% K0 XOR op
%
opad8 = uint8(hex2dec(opad));
K0_opad = K0;
for i = 1 : B
    % result of step 4
    K0_step4_dec = bitxor(uint8(hex2dec(K0_opad((i - 1) * 2 + 1 : i*2))), ipad8);
    K0_opad((i - 1) * 2 + 1 : i*2) = dec2hex(K0_step4_dec, 2);
end
K0_opad = lower(K0_opad);
fprintf('\n K0 XOR ipad is: %s \n', K0_opad);
%
% step 9
%
KKK = strcat(K0_opad, K0_ipad_text_HASH);
HASH = SHA3_hex(KKK, HASH_type, HASH_len);
fprintf('\n HASH result KKK is: %s \n', HASH);
%
%
MAC = HASH(1 : 2*MAC_len);
fprintf('\n MAC is: %s \n', MAC);

