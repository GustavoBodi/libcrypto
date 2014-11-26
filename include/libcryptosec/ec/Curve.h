#ifndef CURVE_H_
#define CURVE_H_

/* c++ library includes */
#include <string>

/* local includes */
#include <libcryptosec/BigInteger.h>

 /**
 * @brief Classe usada para representar curvas elípticas.
 * Esta classe possui funções para que os parâmetros das curvas sejam obtidos
 * ou gerados a partir de um arquivo em PEM/DER
 * @ingroup Util
 */
class Curve {

public:

	Curve();

	/**
	 * Cria uma curva elíptica a partir da descrição de seus parâmetros codificados em DER.
	 * @param encoded parâmetros de curva o formato DER.
	 */
	Curve(ByteArray &encoded);

	/**
	 * Cria uma curva elíptica a partir da descrição de seus parâmetros codificados em PEM.
	 * @param encoded parâmetros de curva o formato PEM.
	 */
	Curve(std::string &encoded);

	~Curve();

	const BIGNUM * BN_a() const throw();

	const BIGNUM * BN_b() const throw();

	const BIGNUM * BN_p() const throw();

	const BIGNUM * BN_x() const throw();

	const BIGNUM * BN_y() const throw();

	const BIGNUM * BN_order() const throw();

	const BIGNUM * BN_cofactor() const throw();

	std::string oid, name;
	BigInteger *a, *b, *p, *x, *y, *order, *cofactor;

	static const std::string notSpecified;

};
#endif /* CURVE_H_ */