#include <libcryptosec/Hmac.h>

Hmac::Hmac() {
	this->state = Hmac::NO_INIT;
	this->ctx = HMAC_CTX_new();
}

Hmac::Hmac(std::string key, MessageDigest::Algorithm algorithm) throw (HmacException) {
	this->state = Hmac::NO_INIT;
	this->ctx = HMAC_CTX_new();
	this->init( key, algorithm );
}

Hmac::Hmac(ByteArray key, MessageDigest::Algorithm algorithm) throw (HmacException) {
	this->state = Hmac::NO_INIT;
	this->ctx = HMAC_CTX_new();
	this->init( key, algorithm );
}

Hmac::Hmac(std::string key, MessageDigest::Algorithm algorithm, Engine &engine) throw (HmacException) {
	this->state = Hmac::NO_INIT;
	this->ctx = HMAC_CTX_new();
	this->init( key, algorithm, engine );
}

Hmac::Hmac(ByteArray key, MessageDigest::Algorithm algorithm, Engine &engine) throw (HmacException) {
	this->state = Hmac::NO_INIT;
	this->ctx = HMAC_CTX_new();
	this->init( key, algorithm, engine );
}

Hmac::~Hmac() {
	HMAC_CTX_free(this->ctx);
}

void Hmac::init(ByteArray &key, MessageDigest::Algorithm algorithm) throw (HmacException) {
	if (this->state != Hmac::NO_INIT)
	{
		HMAC_CTX_reset( this->ctx ); //martin: HMAC_CTX_cleanup -> HMAC_CTX_free, see openssl1.1.0c/CHANGES:647
	}

	this->algorithm = algorithm;
	const EVP_MD *md = MessageDigest::getMessageDigest( this->algorithm );
	int rc = HMAC_Init_ex( this->ctx, (void*)key.getDataPointer(), key.size(), md, NULL );
	if (!rc)
	{
		this->state = Hmac::NO_INIT;
		throw HmacException(HmacException::CTX_INIT, "Hmac::init");
	}

	this->state = Hmac::INIT;
}

void Hmac::init(ByteArray &key, MessageDigest::Algorithm algorithm, Engine &engine) throw (HmacException) {
	if (this->state != Hmac::NO_INIT)
	{
		HMAC_CTX_reset( this->ctx ); //martin: HMAC_CTX_cleanup -> HMAC_CTX_free, see openssl1.1.0c/CHANGES:647
	}

	this->algorithm = algorithm;
	const EVP_MD *md = MessageDigest::getMessageDigest( this->algorithm );
	int rc = HMAC_Init_ex( this->ctx, (void*)key.getDataPointer(), key.size(), md, engine.getEngine() );
	if (!rc)
	{
		this->state = Hmac::NO_INIT;
		throw HmacException(HmacException::CTX_INIT, "Hmac::init");
	}

	this->state = Hmac::INIT;
}

void Hmac::init(std::string key, MessageDigest::Algorithm algorithm) throw (HmacException) {
	ByteArray k( key );
	this->init( k, algorithm );
}

void Hmac::init(std::string key, MessageDigest::Algorithm algorithm, Engine &engine) throw (HmacException) {
	ByteArray k( key );
	this->init( k, algorithm, engine );
}

void Hmac::update(ByteArray &data) throw (HmacException, InvalidStateException) {
	if (this->state == Hmac::NO_INIT)
	{
		throw InvalidStateException("Hmac::update");
	}
	int rc = HMAC_Update( this->ctx, data.getDataPointer(), data.size() );
	if (!rc)
	{
		throw HmacException(HmacException::CTX_UPDATE, "Hmac::update");
	}
	this->state = Hmac::UPDATE;
}

void Hmac::update(std::string data) throw (HmacException, InvalidStateException) {
	ByteArray content( data );
	this->update( content );
}

void Hmac::update(std::vector<std::string> &data) throw (HmacException, InvalidStateException) {
	for(int unsigned i = 0; i < data.size(); i++){
		this->update(data[i]);
	}
}

void Hmac::update(std::vector<ByteArray> &data) throw (HmacException, InvalidStateException) {
	for(int unsigned i = 0; i < data.size(); i++){
		this->update(data[i]);
	}
}  

ByteArray Hmac::doFinal(ByteArray &data) throw (HmacException, InvalidStateException) {
	this->update( data );
	return this->doFinal();
}

ByteArray Hmac::doFinal(std::string data) throw (HmacException, InvalidStateException) {
	this->update( data );
	return this->doFinal();
}

ByteArray Hmac::doFinal() throw (HmacException, InvalidStateException) {
	if (this->state == Hmac::NO_INIT || this->state == Hmac::INIT)
	{
		throw InvalidStateException("Hmac::doFinal");
	}

	unsigned int size;
	unsigned char *md = new unsigned char[EVP_MAX_MD_SIZE + 1];
	int rc = HMAC_Final( this->ctx, md, &size );
	HMAC_CTX_reset( this->ctx ); //martin: HMAC_CTX_cleanup -> HMAC_CTX_free, see openssl1.1.0c/CHANGES:647
	this->state = Hmac::NO_INIT;
	if (!rc)
	{
		delete( md );
		throw HmacException(HmacException::CTX_FINISH, "Hmac::doFinal");
	}

	ByteArray content;
	content.setDataPointer( md, size );

	return content;
}
