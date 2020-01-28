# Direccionamiento IPv6

Las direcciones IPv6 son identificadores de 128 bits para interfaces y conjuntos de interfaces 
(donde "interfaz" es como se define en la Sección 2 de [IPV6]).
Hay tres tipos de direcciones:

Unicast: un identificador para una sola interfaz. 
Un paquete enviado a la dirección de unidifusión se entrega a la interfaz identificada por esa dirección

Anycast: un identificador para un conjunto de interfaces (normalmenteperteneciente a diferentes nodos). 
Un paquete enviado a una unicast es entrega a una de las interfaces identificada por esa dirección (la "más cercana", según
a la medida de distancia de los protocolos de enrutamiento).

Multidifusión: un identificador para un conjunto de interfaces (normalmente perteneciente a diferentes nodos). 
Un paquete enviado a la dirección de multidifusión se entrega a todas las interfaces identificado por esa dirección.

# 2.1 Modelo de direccionamiento

Las direcciones IPv6 de todos los tipos se asignan a interfaces, no a nodos.
Una dirección de unidifusión IPv6 se refiere a una única interfaz. ya que cada
interfaz pertenece a un solo nodo, cualquiera de las interfaces de ese nodo '
pueden usar las direcciones de unidifusión como un identificador para el nodo.

Se requiere que todas las interfaces tengan al menos una direccion de unidifusion de enlace local  
(vea la Sección 2.8 para direcciones adicionales requeridas). 
Una unica interface también puede tener múltiples direcciones IPv6 de cualquier tipo
(unicast, anycast y multicast) o scope. Direcciones de unidifusión con un alcance mayor que 
el alcance del enlace no se necesita para las interfaces que no son usadas 
como origen o destino de ningún paquete IPv6 hacia o desde no vecinos.
Esto a veces es conveniente para interfaces punto a punto. Hay una excepción a este modelo de direccionamiento:

Se puede asignar una dirección de unidifusión o un conjunto de direcciones de unidifusión a
múltiples interfaces físicas si la implementación trata múltiples interfaces físicas como una interfaz al presentarla
a la capa de internet. Esto es útil para compartir la carga entre múltiples interfaces físicas.

Actualmente, IPv6 continua con el modelo IPv4 en el que el prefijo de una subnet es asociado con un link. Multiples
prefijos de subnet pueden ser asignados a el mismo link.

# 2.2 Representación de Direcciones ocmo texto

Hay tres formas convencionales para representar direcciones IPv6 como

- cadenas de texto:

1. La forma preferida es **x: x: x: x: x: x: x: x**, donde la 'x es representa una pieza de cuatro 
dígitos hexadecimales de las ocho piezas de 16 bits de la dirección.
Ejemplos:

         ABCD: EF01: 2345: 6789: ABCD: EF01: 2345: 6789

         2001: DB8: 0: 0: 8: 800: 200C: 417A

Tenga en cuenta que no es necesario escribir los ceros iniciales en un campo individual, 
pero debe haber al menos un número en cada campo (excepto para el caso descrito en 2.).

2. Debido a algunos métodos de asignación de ciertos estilos de direcciones IPv6, 
será común que las direcciones contengan cadenas largas de ceros (bits). 
Con el fin de escribir facilmente direcciones que contengan cero bits, 
una sintaxis especial está disponible para comprimir los ceros.
El uso de ```::``` indica uno o más grupos de 16 bits de ceros.
El ```::``` solo puede aparecer una vez en una dirección. El ```::``` también puede ser usado para comprimir ceros iniciales o finales en una dirección.

Por ejemplo, las siguientes direcciones

    2001: DB8: 0: 0: 8: 800: 200C: 417A una dirección unicast
    FF01: 0: 0: 0: 0: 0: 0: 101 una dirección de multidifusión
    0: 0: 0: 0: 0: 0: 0: 1 la dirección de bucle invertido
    0: 0: 0: 0: 0: 0: 0: 0 la dirección no especificada

puede ser representado como

    2001: DB8 :: 8: 800: 200C: 417A una dirección unicast
    FF01 :: 101 una dirección de multidifusión
    :: 1 la dirección de bucle invertido
    :: la dirección no especificada

3. Una forma alternativa que a veces es más conveniente cuando se trata con un entorno mixto de nodos IPv4 e IPv6 es
x: x: x: x: x: x: d.d.d.d, donde las 'x' son los valores hexadecimales de las seis piezas de alto orden de 16 bits de la dirección, y las 'd' son los valores decimales de las cuatro piezas de bajo orden de 8 bits de la dirección (representación estándar de IPv4).
Ejemplos:

    0: 0: 0: 0: 0: 0: 13.1.68.3

    0: 0: 0: 0: 0: FFFF: 129.144.52.38

o en forma comprimida:

    :: 13.1.68.3

    :: FFFF: 129.144.52.38


# 2.3 Representación de prefijos de dirección en texto

La representación de texto de los prefijos de dirección IPv6 es similar a la
forma en que los prefijos de dirección IPv4 se escriben en interdominios sin clase.
Notación de enrutamiento (CIDR). Un prefijo de dirección IPv6 es representado por la notación:

    dirección ipv6 / longitud del prefijo

dónde

    ipv6-address es una dirección IPv6 en cualquiera de las anotaciones enumeradas
                      en la Sección 2.2.

    la longitud del prefijo es un valor decimal que especifica cuántos de
    los bits contiguos más a la izquierda de la dirección comprenden el prefijo

Por ejemplo, las siguientes son representaciones legales de los 60 bits
prefijo 20010DB80000CD3 (hexadecimal):

    2001: 0DB8: 0000: CD30: 0000: 0000: 0000: 0000/60
    2001: 0DB8 :: CD30: 0: 0: 0: 0/60
    2001: 0DB8: 0: CD30 :: / 60

Las siguientes NO son representaciones legales del prefijo anterior:

    2001: 0DB8: 0: CD3/60 puede eliminar los ceros iniciales, pero no los ceros finales, 
    dentro de cualquier fragmento de 16 bits de la dirección

    2001: 0DB8 ::CD30 / 60 la direccion a la izquierda de "/" se expande a 2001: 0DB8: 0000: 0000: 0000: 0000: 0000: CD30

    2001: 0DB8 :: CD3 / 60 lamdireccion a la izquierda de "/" se expande a 2001: 0DB8: 0000: 0000: 0000: 0000: 0000: 0CD3

Al escribir una dirección de nodo y un prefijo de esa dirección de nodo 
(por ejemplo, el prefijo de subred del nodo), los dos se pueden combinar de la siguiente manera:

la dirección del nodo 
```
    2001: 0DB8: 0: CD30: 123: 4567: 89AB: CDEF
```
y su número de subred 
```
    2001: 0DB8: 0: CD30 :: / 60
```
puede abreviarse como 
```   
    2001: 0DB8: 0: CD30: 123: 4567: 89AB: CDEF / 60
```

# 2.4 Identificación del tipo de dirección

El tipo de una dirección IPv6 se identifica mediante los bits de orden superior de la dirección, como sigue:

Tipo de direccion| Prefijo binario | Notacion IPv6 | Sección
--- | --- | --- | --- |
Sin especificar | 00 ... 0 (128 bits)  | :: / 128  | 2.5.2
Loopback| 00 ... 1 (128 bits)|:: 1/128| 2.5.3
Multicast    |        11111111     |               FF00 ::/8     |      2.7
Enlace local unicast | 1111111010    |              FE80 ::/10    |      2.5.6
Global Unicast    |   (todo lo demás)

Las direcciones de difusión se toman de los espacios de direcciones de unidifusión (de cualquier
alcance) y no son sintácticamente distinguibles de las direcciones de unidifusión.

# 2.5 Direcciones de unidifusión

Las direcciones de unidifusión IPv6 se pueden agregar con prefijos de longitud arbitraria.

Hay varios tipos de direcciones de unidifusión en IPv6, en particular,
Unidifusión global, unidifusión local del sitio (en desuso, consulte la Sección 2.5.7),
y unidifusión local de enlace.

# 2.5.1 Identificadores de interfaz

Los identificadores de interfaz en las direcciones de unidifusión IPv6 se utilizan para identificar
interfaces en un enlace. Deben ser únicos dentro de un prefijo de subred. 
Se recomienda que el mismo identificador de interfaz no sea
asignado a diferentes nodos en un enlace. También pueden ser únicos durante
Un alcance más amplio. En algunos casos, el identificador de una interfaz será
derivado directamente de la dirección de la capa de enlace de esa interfaz. El mismo
identificador de interfaz se puede utilizar en varias interfaces en un solo nodo, 
siempre que estén conectados a diferentes subredes.

Tenga en cuenta que la unicidad de los identificadores de interfaz es independiente de
La singularidad de las direcciones IPv6. Por ejemplo, una direccion de unidifusión global
se puede crear con un identificador de interfaz de ámbito local y 
La dirección de enlace local se puede crear con un identificador de  interfaz de alcance universal

# 2.5.2 La dirección no especificada

La dirección ```0: 0: 0: 0: 0: 0: 0: 0``` se denomina dirección no especificada. Eso
nunca debe asignarse a ningún nodo. Indica la ausencia de una direccion.
Un ejemplo de su uso está en el campo Dirección de origen de
cualquier paquete IPv6 enviado por un host inicializador antes de que haya aprendido
Su propia dirección.

La dirección no especificada no debe usarse como dirección de destino
de paquetes IPv6 o en encabezados de enrutamiento IPv6. Un paquete IPv6 con
la dirección de origen no especificada nunca debe ser enviada por un enrutador IPv6.

# 2.5.3 La dirección de bucle invertido

La dirección de unidifusión ```0: 0: 0: 0: 0: 0: 0: 1``` se denomina dirección de bucle invertido.
Puede ser utilizado por un nodo para enviarse un paquete IPv6 asi mismo. 
Debería no ser asignado a ninguna interfaz física. Se trata como teniendo
Ámbito de enlace local, y puede considerarse como la direccion de unidifusión de enlace local
de una interfaz virtual (típicamente llamada "loopback interfaz ") a un enlace imaginario que no va a ninguna parte.

La dirección de bucle invertido no debe usarse como dirección de origen de paquetes IPv6
que se envían fuera de un solo nodo. Un paquete IPv6 con una dirección de destino de loopback nunca debe enviarse fuera de un
nodo único y nunca debe ser reenviado por un enrutador IPv6. Un paquete
recibido en una interfaz con una dirección de destino de loopback debe ser dejado caer


# 2.5.4 Direcciones globales Unicast

n bits | m bits | 128-n-m bits
--- | --- | ---
Global routing prefix | subnet ID | Interface ID

# 2.5.6 Link-local Direccion unicast IPv6


10 bits | 54 bits | 64 bits
--- | --- | ---
1111111010 | 0 | Interface ID

# 2.7.1 Direcciones de multidifusión predefinidas

Las siguientes direcciones de multidifusión conocidas están predefinidas. los
ID de grupo definidos en esta sección se definen para valores de alcance explícito.

Uso de estos ID de grupo para cualquier otro valor de alcance, con el indicador T
igual a 0, no está permitido.

```
Estas direcciones no deberan ser reservadas a ningun grupo multicast

Direcciones Multicast reservadas:     FF00:0:0:0:0:0:0:0
                                      FF01:0:0:0:0:0:0:0
                                      FF02:0:0:0:0:0:0:0
                                      FF03:0:0:0:0:0:0:0
                                      FF04:0:0:0:0:0:0:0
                                      FF05:0:0:0:0:0:0:0
                                      FF06:0:0:0:0:0:0:0
                                      FF07:0:0:0:0:0:0:0
                                      FF08:0:0:0:0:0:0:0
                                      FF09:0:0:0:0:0:0:0
                                      FF0A:0:0:0:0:0:0:0
                                      FF0B:0:0:0:0:0:0:0
                                      FF0C:0:0:0:0:0:0:0
                                      FF0D:0:0:0:0:0:0:0
                                      FF0E:0:0:0:0:0:0:0
                                      FF0F:0:0:0:0:0:0:0
```

Todas las direcciones de nodos

Estas direcciones identifican el grupo de todos los nodos IPv6

**escope = 1** ```interface-local```
**escope = 2** ``link-local``
```
FF01:0:0:0:0:0:0:1
FF02:0:0:0:0:0:0:1
```


# 2.8 Direcciones requeridas de un nodo

Se requiere un host para reconocer las siguientes direcciones como
identificándose a sí mismo:

    o Su dirección de enlace local requerida para cada interfaz.

    o Cualquier dirección Unicast y Anycast adicional que haya sido
    configurado para las interfaces del nodo (manualmente o
    automáticamente).

    o La dirección de bucle invertido.

    o Las direcciones de multidifusión de todos los nodos definidas en la Sección 2.7.1.

    o La dirección de multidifusión del nodo solicitado para cada una de sus direcciones de  unidifusión y
        direcciones de difusión ilimitada

    o Direcciones de multidifusión de todos los otros grupos a los que el nodo
    pertenece

Se requiere un enrutador para reconocer todas las direcciones que el host
requirio reconocer, más las siguientes direcciones como identificandose así mismo:

    o Las direcciones Anycast del enrutador de subred para todas las interfaces para las cuales
        Está configurado para actuar como un enrutador.

    o Todas las demás direcciones Anycast con las que se ha utilizado el enrutador
        configurado

    o Las direcciones de multidifusión de todos los enrutadores definidas en la Sección 2.7.1.