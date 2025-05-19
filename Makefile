LIBS=$(LDFLAGS) -L./
CFLAGS+=-I./test
DEBUG=-g

.PHONY: all clean

TEST_APP_SOURCE = test/pkcs11_test_app.c
OBJS:= pkcs11_test_app.o
TARGET:= pkcs11_test_app
LIBRARY:= libqca-pkcs11.so

all: $(LIBRARY) $(TARGET)

.c.o:
	$(call progress, Building $@)
	${Q}$(CC) ${DEBUG} ${LIBDIRS} ${INCDIRS} $(CFLAGS) ${LIBS} -c $^

$(LIBRARY): src/pkcs11_crypto.c src/pkcs11_api.c src/pkcs11_session.c src/pkcs11_object.c src/pkcs11_mech.c src/pkcs11_init.c
	$(call progress, Building $@)
	${Q}$(CC) ${DEBUG} ${LIBDIRS} ${INCDIRS} $(CFLAGS) ${LIBS} -shared -o $@.debug $^
	${Q}$(STRIP) $@.debug -o $@


$(TARGET): $(TEST_APP_SOURCE)
	$(call progress, Building $@ from ${objs})
	$(CC) ${DEBUG} ${LIBDIRS} ${INCDIRS} $(CFLAGS) ${LIBS} -lqca-pkcs11 -o $@.debug $<
	${Q}$(STRIP) $@.debug -o $@

clean:
	rm -f $(TARGET) $(OBJS) $(LIBRARY) *.debug
