LDFLAGS="-L/usr/local/lib/"
CFLAGS=-I/usr/local/include -I./include -I/usr/local/include
TESTFLAGS=-lcriterion
SSLFLAGS=-lssl
CRYPTOLAGS=-lcrypto

all: sm3test sm2test

clean: cleanall

cleanall:
	rm -rf *.o *.so *.dylib sm2_test sm2_test2


##################
# sm2rr
##################
sm2: sm2rr
	./sm2rr

sm2rr: sm2rr.o sm2_sign.o sm3.o bn_lib.o err.o
	gcc -o sm2rr sm2rr.o sm2_sign.o sm3.o bn_lib.o err.o $(SSLFLAGS) $(CRYPTOLAGS) $(LDFLAGS) $(CFLAGS)

sm2rr.o: test/sm2rr.c
	gcc -c test/sm2rr.c

####################
#     sm2 part     #
####################

sm2test: sm2_test
	./sm2_test

sm2_test: sm2_sign.o sm2_test.o sm3.o bn_lib.o err.o
	gcc -o sm2_test sm2_sign.o sm2_test.o sm3.o bn_lib.o err.o  $(TESTFLAGS) $(SSLFLAGS) $(CRYPTOLAGS) $(LDFLAGS) $(CFLAGS)

sm2_test2: sm2test.o sm2_sign.o sm3.o bn_lib.o err.o
	gcc -o sm2_test2 sm2test.o sm2_sign.o sm3.o bn_lib.o err.o $(SSLFLAGS) $(CRYPTOLAGS) $(LDFLAGS) $(CFLAGS)

sm2test.o: test/sm2test.c
	gcc -c test/sm2test.c

err.o:
	gcc -c crypto/err/err.c

sm2_asn1.o: crypto/sm2/sm2_asn1.c
	gcc -fPIC -c crypto/sm2/sm2_asn1.c $(CFLAGS)

sm2_enc.o: crypto/sm2/sm2_enc.c
	gcc -fPIC -c crypto/sm2/sm2_enc.c $(CFLAGS)

sm2_id.o: crypto/sm2/sm2_id.c
	gcc -fPIC -c crypto/sm2/sm2_id.c $(CFLAGS)

sm2_kap.o: crypto/sm2/sm2_kap.c
	gcc -fPIC -c crypto/sm2/sm2_kap.c $(CFLAGS)

sm2_kmeth.o: crypto/sm2/sm2_kmeth.c
	gcc -fPIC -c crypto/sm2/sm2_kmeth.c $(CFLAGS)

sm2_sign.o: crypto/sm2/sm2_sign.c
	gcc -fPIC -c crypto/sm2/sm2_sign.c  $(CFLAGS)

bn_lib.o:
	gcc -c crypto/bn/bn_lib.c $(CFLAGS)



sm2_test.o: test/sm2_test.c
	gcc -c test/sm2_test.c  $(CFLAGS)

sm2clean: 
	rm -rf sm2_sign.o sm2_test.o sm2_test bn_lib.o

###################
#     sm3 part    #
###################

sm3test: sm3_test
	./sm3_test
sm3_test: sm3.o sm3_test.o 
	gcc -o sm3_test sm3.o sm3_test.o $(TESTFLAGS) $(SSLFLAGS) $(CRYPTOLAGS) $(LDFLAGS) $(CFLAGS)
sm3share: sm3.o
	gcc -fPIC -shared sm3.o -o libsm3.dylib
sm3.o: include/sm3.h crypto/sm3/sm3.c 
	gcc -c crypto/sm3/sm3.c include/sm3.h $(CFLAGS)
sm3_test.o: test/sm3_test.c include/sm3.h
	gcc -c test/sm3_test.c include/sm3.h  $(CFLAGS)

sm3clean: 
	rm -rf sm3.o sm3_test.o sm3_test
