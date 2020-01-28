# 1. Información general

   El protocolo Ad hoc On-Demand Distance Vector Version 2 (AODVv2)
   permite el enrutamiento dinámico entre múltiples dispositivos móviles enrutadores participantes
   que desean establecer y mantener una red ad hoc.Las operaciones básicas del protocolo AODVv2 son descubrimiento de ruta y mantenimiento ruta. AODVv2 no requiere nodos para mantener rutas a
   destinos que no están en comunicación activa. AODVv2 permite
   nodos móviles para responder a roturas de enlaces y cambios en la conectividad de la red.

# 1.1. Protocolos de enrutamiento por vector de distancia

   AODVv2 es un protocolo de enrutamiento de vector de distancia, lo que significa que las rutas
   se almacenan con información sobre el próximo salto (vector para reenvío) y la métrica o el costo de usar la ruta (una "distancia" al destino a lo largo de esa ruta). Típicamente, si hay múltiples rutas disponibles para ser seleccionados a un destino particular , la ruta con el menor costo (por ejemplo, la distancia más corta) se elige para propósito de reenviar paquetes a ese destino. Vector de distancia
   (Bellman-Ford) los protocolos de enrutamiento fueron históricamente vulnerables a lo que
   se hizo conocido como el problema de "contar hasta el infinito". Ese problema
   hace que las rutas empeoren rápidamente con el tiempo y resulta en una incapacidad del enrutador para detectar actualizaciones de  enrutamiento fuera de secuencia y posterior retransmisión de información obsoleta. 
   
   AODVv2 usa secuencia números para asegurar la detección de información de enrutamiento obsoleto, como se hizo
   previamente en DSDV y como se describe en [Perkins94]. La operación de AODVv2 es, por lo tanto, libre de bucles y ofrece una convergencia rápida cuando
   la topología de red ad hoc cambia (normalmente, cuando un nodo se mueve en la red) Cuando los enlaces se rompen, AODVv2 provoca que el conjunto de nodos afectados sean notificados para que puedan invalidar las rutas
   usando el enlace roto.

AODVv2 almacena un número de secuencia de destino para cada entrada de ruta.
   El numero de secuencia de destinacion es creado por el destino incluido junto con cualquier información de ruta que envíe al nodo requerido. El uso de números de secuencia de destino garantiza la libertad de bucle y
   Es simple de programar. Dada la elección entre dos rutas a un
   destino, se requiere un nodo solicitante para seleccionar el que tiene
   mayor número de secuencia.

# 1.2. Mecanismos básicos de protocolo

   Los mecanismos básicos del protocolo son los siguientes. AODVv2 es un protocolo reactivo,lo que significa que el descubrimiento de ruta se inicia solo cuando una ruta al objetivo es necesario (es decir, cuando el cliente de un enrutador tiene datos para enviar
   (ver Sección 4.2)). Para este propósito, AODVv2 usa la solicitud de ruta
   (RREQ) y mensajes de respuesta de ruta (RREP) de la siguiente manera: un RREQ es
   distribuido a través de la red. Enrutadores (que no sean el objetivo)
   recibir el RREQ retransmitirlo y también almacenar una ruta inversa de regreso
   al autor de la RREQ.

![alt text](image.png "Title")

Figura 1: Inundando un RREQ a través de la red


En la figura 1, el nodo 'S' necesita descubrir una ruta a un
nodo de destino 'D'. S genera un RREQ para inundar la red.  
El RREQ atraviesa los nodos A, B, J, K, L y M antes de que finalmente
llege al nodo de destino D. El RREQ también probablemente sea recibido y retransmitido por muchos otros nodos en la red. Cada nodo intermedio que recibe el RREQ almacena un
ruta inversa de regreso al nodo S para que la comunicación entre S y D pueda ser establecida
en caso de que el nodo intermedio reciba un RREP en respuesta a la RREQ.

Cuando el objetivo recibe el RREQ, responde con un RREP, que es
luego retransmitido al originador a lo largo de la ruta almacenada por los
enrutadores intermedios. Se incluye un valor métrico dentro de los mensajes.
para indicar el costo de la ruta.

``` S <--- A <--- B <--- J <--- K <--- L <--- M <--- D```

Figura2 Enviando un RREP de regreso al nodo S

En la figura 2, el nodo 'D' transmite un RREP hacia S. 
Nodo M ha almacenado una ruta de regreso a S por medio del nodo L. 
El nodo L ha almacenado una ruta de regreso a S a través del nodo K, 
y así sucesivamente. Además, cada nodo que recibe el RREP utiliza la información en el RREP para almacenar una ruta al nodo 'D'. Por ejemplo, el RREP contiene la métrica que describe el costo de la ruta desde un nodo intermedio X al nodo D, también como información sobre el próximo salto hacia D, es decir, el nodo que
transmitió el RREP a X.

AODVv2 usa números de secuencia como se describió anteriormente para identificar
información de enrutamiento obsoleta y compara valores de métrica de ruta para determinar si
Las rutas anunciadas pueden formar bucles. 

El mantenimiento de la ruta incluye
confirmando la bidireccionalidad de los enlaces a los enrutadores AODVv2 de siguiente salto,
administrar tiempos de espera de ruta, utilizando mensajes de error de ruta (RERR) para informar a 
otros enrutadores de enlaces rotos y que reaccionan a los mensajes de error de ruta recibido

AODVv2 requiere que se intercambien indicaciones entre AODVv2 y el
subsistema de reenvío para las siguientes condiciones:


o un paquete necesita ser reenviado y una ruta necesita ser descubierta
      (Esto sucede debido a la naturaleza bajo demanda de AODVv2)

o el reenvío de paquetes falla, para informar un error de ruta

o el reenvío de paquetes se realiza correctamente, para administrar los tiempos de espera de ruta.

   Seguridad para la autenticación de enrutadores AODVv2 y encriptación de
   los mensajes de control se logran utilizando los TLV TIMESTAMP e ICV
   definido en [RFC7182].

# 1.3. Comparación con RFC 3561

   AODVv2 funciona de manera muy similar a AODV [RFC3561].
   El mecanismo para el descubrimiento de ruta es básicamente el mismo, por lo que 
   se pueden esperar resultados de rendimiento similares. En comparación con AODV, 
   AODVv2 movió algunas características fuera del alcance del documento, en particular
   respuestas de ruta intermedia y búsqueda de anillo expandida. Sin embargo, esto
   documento ha sido diseñado para permitir la especificación de esas características
   en un documento separado.

   Los mensajes de control AODVv2 se definen como conjuntos de datos. Como se describe en la 
   Sección 8, estos conjuntos de datos se pueden asignar a elementos de mensaje utilizando
   el formato de paquete / mensaje MANET generalizado definido en [RFC5444] y
   enviado utilizando los parámetros en [RFC5498]. Refinamientos adicionales se han
   hecho para tiempos de espera de ruta y gestión estatal. Otras asignaciones
   para los conjuntos de datos para los mensajes de control son posibles.

   En comparación con AODV [RFC3561], los siguientes mecanismos de protocolo han cambiado:

   o La verificación de la bidireccionalidad del enlace ha sido sustancialmente
      mejorada

   o Se pueden usar métricas alternativas para determinar la calidad de la ruta

   o Se ha mejorado el soporte para múltiples interfaces

   o Se ha agregado soporte para direcciones IP de interfaz múltiple

   o Un nuevo modelo de seguridad que permite verificaciones de integridad de extremo a extremo ha sido
      adicionada

   o Los formatos de mensajes se han actualizado y cumplen con
      [RFC5444].

   o Se eliminaron los mensajes de saludo y la reparación local.

   o Multihoming es compatible.

   AODVv2 no ha sido diseñado para ser interoperable con AODV. Sin embargo,
   sería sencillo permitir que ambos protocolos se usen en
   misma red ad hoc siempre que se usen métricas compatibles.

   # 2. Terminologia

   **Address Block (bloque de direcciones)**
      Una lista de direcciones junto con el tipo de dirección para cada dirección (ver
      Sección 8).

   **AddressList (Lista de direcciones)**
      Una lista de direcciones IP como se usa en los mensajes AODVv2. La familia de  direcciónes IP
      es determinada, por ejemplo, por la elección de parámetros en
      [RFC5444] u otra capa de calce entre AODVv2 y la capa dered


   **AckReq**
      Se utiliza en un mensaje de confirmación de respuesta de ruta para indicar que un
      reconocimiento de respuesta de ruta es esperado a cambio (ver
      Sección 7.3).

   **AdvRte**
      Una ruta anunciada en un mensaje de ruta entrante (RREQ o RREP).

   **AODV Router (Enrutador AODVv2)**
      Un dispositivo direccionable IP en la red ad hoc que realiza
      Operaciones del protocolo AODVv2 especificadas en este documento.

   **Tiempo actual**
      La hora actual mantenida por el enrutador AODVv2.

   **Ruta inválida**
      Una ruta que no se puede usar para reenviar pero que aún contiene
      Información útil del número de secuencia.

   **Ruta Local**
      Una entrada en el Conjunto de rutas locales como se define en la Sección 4.5.

   **MANET**
      Una red ad hoc móvil como se define en [RFC2501].

   **MetricType**
      El tipo de métrica para un valor de métrica incluido en un mensaje (consulte
      Sección 13.4).

   **MetricTypeList**
      Una lista de tipos de indicadores asociados con las direcciones en
      la lista de direcciones de un mensaje de error de ruta.

   **Vecino**
      Un enrutador AODVv2 desde el cual se ha recibido un mensaje RREQ o RREP. 
      Los vecinos intercambian información de enrutamiento y verifican
      bidireccionalidad del enlace a un vecino antes de instalar un
      ruta a través de ese vecino en el conjunto de rutas locales.

    **OrigAddr**
      La dirección IP de origen del paquete IP que activa el descubrimiento de ruta.

   **OrigMetric**
      El valor métrico asociado con la ruta a OrigPrefix.

   **OrigPrefix**
      El prefijo configurado en la entrada del conjunto de clientes de enrutador que
      incluye OrigAddr.

   **OrigPrefixLen**
      La longitud del prefijo, en bits, configurada en el conjunto de clientes del enrutador
      entrada que incluye OrigAddr.

   **OrigSeqNum**
      El número de secuencia del enrutador AODVv2 que originó el
      Solicitud de ruta en nombre de OrigAddr.

   **PktSource**
      La dirección de origen del paquete IP que activó un error de ruta
      mensaje.

   **PrefixLengthList**
      Una lista de longitudes de prefijo de enrutamiento asociadas con las direcciones en
      la Lista de direcciones de un mensaje.

   **Reactivo**
      Realizado solo en reacción a eventos específicos. En AODVv2, rutas
      se solicitan solo cuando se deben reenviar paquetes de datos. En
      este documento, "reactivo" es sinónimo de "bajo demanda".

   **RERR (error de ruta)**
      El tipo de mensaje AODVv2 utilizado para indicar que un enrutador AODVv2
      no tiene una ruta local válida hacia uno o más destinos.

   **RERR_Gen (enrutador generador de RERR)**
      El enrutador AODVv2 que genera un mensaje de error de ruta.

   **RerrMsg (Mensaje RERR)**
      Un mensaje de error de ruta (RERR).

   **Routable Unicast IP Address (Dirección IP de unidifusión enrutable)**
      Una dirección IP de unidifusión que tiene el alcance suficiente para ser reenviada
      por un enrutador. Direcciones IP de unidifusión de alcance global y Único
      Las direcciones locales (ULA) [RFC4193] son ​​ejemplos de unidifusión enrutable
      Direcciones IP.

   **Cliente enrutador** 
    Una dirección dentro de un rango de direcciones configurado en un enrutador AODVv2,
      en nombre del cual ese enrutador iniciará y responderá al descubrimiento de rutas.
      Estas direcciones pueden ser utilizadas por el enrutador AODVv2 por sí mismo o por 
      dispositivos a los que se pueda acceder sin atravesar otro Enrutador AODVv2.

   **RREP (respuesta de ruta)**
      El tipo de mensaje AODVv2 utilizado para responder a un mensaje de solicitud de ruta.

   **RREP_Gen (enrutador generador de RREP)**
      El enrutador AODVv2 que genera el mensaje de respuesta de ruta, es decir,
      el enrutador configurado con TargAddr como un cliente de enrutador.

   **RREQ (solicitud de ruta)**
      El tipo de mensaje AODVv2 utilizado para descubrir una ruta a TargAddr y
      distribuir información sobre una ruta a OrigPrefix.

   **RREQ_Gen (enrutador generador de RREQ)**
      El enrutador AODVv2 que genera el mensaje de solicitud de ruta, es decir,
      el enrutador configurado con OrigAddr como un cliente de enrutador.

   ***RteMsg (mensaje de ruta)**
      Un mensaje de solicitud de ruta (RREQ) o de respuesta de ruta (RREP).

   **SeqNum**
      El número de secuencia mantenido por un enrutador AODVv2 para indicar
      información de la ruta actualizada.

   **SeqNumList**
      Una lista de números de secuencia asociados con las direcciones en la
      Lista de direcciones de un mensaje.

   **TargAddr**
      La dirección de destino de una solicitud de ruta, es decir, la dirección de destino del paquete IP que activa el descubrimiento de ruta.

   **TargMetric**
      El valor métrico asociado con la ruta a TargPrefix.

   **TargPrefix**
      El prefijo configurado en la entrada del conjunto de clientes del enrutador que
      incluye TargAddr.

   **TargPrefixLen**
      La longitud del prefijo, en bits, configurada en el conjunto de clientes del enrutador
      entrada que incluye TargAddr.

   **TargSeqNum**
   El número de secuencia del enrutador AODVv2 que originó el
      RRPLY en nombre de TargAddr.

   **Unreachable Address (Dirección inalcanzable)**
      Una dirección informada en un mensaje de error de ruta, como se describe en
      Sección 7.4.1.

   **upstream**
      En la dirección del destino a la fuente (de TargAddr a
      OrigAddr).

   Ruta válida
      Una ruta que se puede usar para reenviar.

   Este documento utiliza las convenciones de notación en la Tabla 1 para simplificar
   el texto.

Notacion | Significado 
--- | --- | ---
Route[Address]| Una ruta hacia la dirección 
Route[Address].Field | Un campo en una ruta hacia la direccion
McMsf.Field | Un campo en una entrada de mensaje de multidifusión
RteMsg.Field | Un campo en cualquiera RREQ o RREP

Tabla1: convencion de notacion

# 3. Declaración de aplicabilidad

   El protocolo de enrutamiento AODVv2 es un protocolo de enrutamiento reactivo diseñado
   para usarse en redes inalámbricas ad hoc móviles, y también puede ser útil en
   redes donde los nodos no son móviles sino ruta económica
   aún se requiere mantenimiento. Un protocolo reactivo solo envía
   mensajes para descubrir una ruta cuando hay datos para enviar en esa
   ruta. Esto requiere una interacción con el plano de reenvío, para
   indicar cuándo se debe reenviar un paquete, en caso de ruta reactiva
   Se necesita un descubridor de rutas. El conjunto de señales intercambiadas entre AODVv2 y
   el plano de reenvío se discute en la Sección 6.4.

   AODVv2 está diseñado para redes ad hoc móviles stub o desconectadas,
   es decir, redes que no son de tránsito o aquellas que no están conectadas a internet.
   Sin embargo, los enrutadores AODVv2 se pueden configurar para realizar funciones de  puerta de enlace
   cuando está conectado a redes externas, como se discute en Seccion 9.

   AODVv2 maneja una amplia variedad de patrones de movilidad y tráfico mediante
   determinación de rutas bajo demanda. En redes con una gran cantidad de
   enrutadores, AODVv2 es el más adecuado para tráfico relativamente escaso
   escenarios en los que cada enrutador reenvía paquetes IP a un pequeño porcentaje
   de direcciones de destino en la red. En tales casos, menos rutas
   son necesarios, y se produce mucho menos tráfico de control. En grande
   redes con patrones de tráfico denso, los mensajes de control AODVv2 pueden
   causar una tormenta de difusión, abrumando la red con mensajes de control
   mensajes. Las prioridades de transmisión descritas en la Sección 6.5
   priorizar el tráfico de mantenimiento de ruta sobre el tráfico de descubrimiento de ruta.

   Los paquetes de datos pueden almacenarse en búfer hasta que una ruta a su destino este
   disponible, como se describe en la Sección 6.6.

   AODVv2 se adapta bien a escenarios reactivos como emergencias y
   ayuda en caso de desastre, donde la capacidad de comunicarse podría ser mas
   importante que estar seguro de operaciones seguras. Para muchas otras aplicaciones de red ad-hoc, en las cuales la operación insegura podría negar el valor de establecer vías de comunicación, es importante para
   enrutadores AODVv2 vecinos establecer asociaciones de seguridad unos con otros.

   AODVv2 proporciona integridad de mensajes y seguridad contra la reproducción
   ataques mediante el uso de valores de verificación de integridad, marcas de tiempo y secuencia de 
   números, como se describe en la Sección 14. Cuando las asociaciones de seguridad han sido
   establecidas, el cifrado se puede utilizar para mensajes AODVv2 para
   asegúrese de que solo los enrutadores de confianza participen en las operaciones de enrutamiento.

   El proceso de descubrimiento de ruta AODVv2 tiene como objetivo establecer una ruta
   en ambas direcciones a lo largo del mismo camino. Los enlaces unidireccionales no son
   adecuados; AODVv2 detectará y excluirá esos enlaces del descubrimientod de ruta. 
   La ruta descubierta está optimizada par la solicitud del router y la ruta que retorna podria no ser una ruta optima.
   
   AODVv2 es aplicable a dispositivos con memoria limitada, ya que solo
   se mantiene un pequeño estado de enrutamiento en cada enrutador AODVv2. AODVv2
   las rutas que no son necesarias para reenviar datos no necesitan ser mantenidas.

   AODVv2 admite enrutadores con múltiples interfaces y múltiples direcciones IP por interfaz. Un enrutador también puede usar la misma dirección IP en múltiples interfaces. 
   
   AODVv2 solo requiere que cada interfaz
   configurad para AODVv2 tenga al menos una dirección IP de unidifusión (consulte
   Sección 4.1). Los procedimientos de asignación de direcciones están fuera del alcance de
   AODVv2.

   AODVv2 admite clientes de enrutador con múltiples interfaces, siempre que
   cada interfaz de Cliente está configurada con su propia dirección IP de unidifusión.

   El algoritmo de enrutamiento en AODVv2 ha sido operado en otras capas
   que la capa de red, usando direcciones apropiadas para la capa.

# 4. Estructuras de datos

# 4.1. Interfaces de red utilizadas por AODVv2

   AODVv2 tiene que mantener información sobre todas las interfaces de red
   configuradas para enviar o recibir mensajes AODVv2. Cualquier interfaz
   Con una dirección IP se puede utilizar. Múltiples interfaces en un simple router
   se puede usar. Múltiples interfaces en el mismo enrutador pueden ser
   configurado con la misma dirección IP; en este caso, suficiente
   la información sobre esas interfaces de red debe ser mantenida por
   el enrutador AODVv2 para determinar cuál de ellos ha recibido un
   mensaje entrante AODVv2. Por ejemplo, a menudo es posible
   determine la interfaz entrante inspeccionando la dirección MAC del
   Encabezado de marco de capa 2.

# 4.2. Conjunto de clientes de enrutador

   Un enrutador AODVv2 descubre rutas para sus propias aplicaciones locales y
   también para sus clientes enrutadores que son accesibles sin atravesar
   otro enrutador AODVv2. Las direcciones utilizadas por estos dispositivos y el
   El enrutador AODVv2 en sí está configurado en el conjunto de clientes de enrutador. Un
   enrutador AODVv2 solo originará Solicitud de mensajes ruta y Respuesta de ruta
   en nombre de sus direcciones de cliente de enrutador configuradas.

   Las entradas del conjunto de clientes de enrutador se configuran manualmente o por mecanismos
   fuera del alcance de este documento. La entrada de cada cliente contiene:

   RouterClient.IPAddress
      Una dirección IP o el inicio de un rango de direcciones que requiere servicios de
      descubrimiento de ruta del enrutador AODVv2.

   RouterClient.PrefixLength
      La longitud, en bits, del prefijo de enrutamiento asociado con el
      RouterClient.IPAddress. Si la longitud del prefijo no es igual a
      longitud de la dirección de RouterClient.IPAddress, el enrutador AODVv2 DEBE
      participar en el descubrimiento de rutas en nombre de todas las direcciones dentro de
      ese prefijo

   RouterClient.Cost
      El costo asociado con llegar a la dirección o rango de direcciónes del cliente.

    
# 4.3. Conjunto de vecinos

   Un conjunto vecinos se utiliza para mantener información sobre vecinos Enrutadores AODVv2. 
   Las entradas del conjunto de vecinos se almacenan cuando los mensajes AODVv2
   son recibidos Si el vecino se elige como próximo salto en una ruta instalada, el enlace al vecino se prueba para bidireccionalidad; El resultado se almacena en el conjunto vecino.

   Las entradas del conjunto vecino DEBEN contener:

   - **Neighbor.IPAddress**
        Una dirección IP del enrutador vecino.

   - **Neoghbr.State**
      Indica si el enlace al vecino es bidireccional.
      Hay tres estados posibles: 
        - Heard( CONFIRMADO). 
        - ESCUCHADO (CONFIRMED).
        - BLACKLISTED
    ESCUCHADO es el estado inicial. 
    CONFIRMADO indica que el enlace al vecino ha sido confirmado como bidireccional.
    BLACKLISTED indica que el enlace al vecino está siendo
    tratado como unidireccional. La sección 6.2 discute cómo monitorear EL enlace bidireccional.

   - **Neighbor.Timeout**.
        Indica la hora a la que se debe actualizar el Neighbor.State:

        - Si el valor de Neighbor.State está en BLACKLISTED, esto indica la
        hora en la que Neighbor.State volverá a HEARD. Este valor es
        calculado en el momento en que el enrutador está en la lista negra y, de manera predeterminada, es
        igual a CurrentTime + MAX_BLACKLIST_TIME.

        - Si Neighbor.State es HEARD, y se ha solicitado un RREP_Ack del vecino, indica la hora a la que Vecino
        se establecerá en BLACKLISTED, si no se ha recibido un RREP_Ack.

        - Si el valor de Neighbour.State es HEARD y no se ha solicitado un RREP_Ack,
        si Neighbor.State está CONFIRMADO, esta vez se establece en INFINITY_TIME.

   - **Neighbor.Interface**
      La interfaz en la que se estableció el enlace al vecino.

   - **Neighbour.AckSeqNum**
      El siguiente número de secuencia a utilizar para el valor TIMESTAMP en un
      Solicitud RREP_Ack, para detectar la reproducción de un RREP_Ack
      respuesta. AckSeqNum se inicializa a un valor aleatorio.


   - **Neighbor.HeardRERRSeqNum**
      El último número de secuencia escuchado utilizado como el valor TIMESTAMP en un
      RERR recibido de este vecino, guardado para detectar la repetición
      de un mensaje RERR. HeardRERRSeqNum se inicializa a cero.

      Consulte la Sección 11.3 y la Sección 11.4 para obtener más información sobre cómo
      Neighbour.AckSeqNum y Neighbour.HeardRERRSeqNum se utilizan.


# 4.4. Números de secuencia

   Los números de secuencia permiten a los enrutadores AODVv2 determinar de forma temporal
   orden de mensajes de descubrimiento de ruta que se originan a partir de un enrutador AODVv2, 
   y así identificar información de enrutamiento obsoleta para que pueda
   ser descartada. El número de secuencia cumple los mismos roles que el
   "Número de secuencia de destino" de DSDV [Perkins94] y el Número de secuencia AODV en [RFC3561]. 
   Los números de secuencia de dos routers diferentes no son comparables; Enrutar mensajes de descubrimiento con
   los números de secuencia que pertenecen a dos enrutadores diferentes no pueden ser comparados para determinar el ordenamiento temporal.

   Cada enrutador AODVv2 en la red DEBE mantener su propio numero de secuencia. 
   Todos los mensajes RREQ y RREP creados por un enrutador AODVv2
   incluiye el número de secuencia del enrutador, reportado como un entero de 16-bit sin signo. 
   Cada enrutador AODVv2 DEBE asegurarse de que su número de secuencia sea
   estrictamente creciente, y que se incrementa en uno (1) cada vez
   se crea un RREQ o RREP, excepto cuando el número de secuencia es 65.535
   (el valor máximo de un entero sin signo de 16 bits), en cuyo caso
   DEBE restablecerse a uno (1) para lograr la envoltura. 
   El valor cero (0) está reservado para indicar que se desconoce el número de secuencia del enrutador.

   Un enrutador AODVv2 DEBE usar su número de secuencia solo en nombre de su
   clientes de enrutadores configurados; Enrutar mensajes reenviados por otros enrutadores
   retener el número de secuencia del originador.

   Para determinar si la información recién recibida es obsoleta y, por lo tanto,
   redundante en comparación con otra información originada por el mismo
   enrutador, se compara el número de secuencia adjunto a la información
   al número de secuencia de información existente sobre la misma ruta.
   La comparación se lleva a cabo restando el numero de secuencia existente
   con el número de secuencia recién recibido, usando aritmetica sin signo. 
   El resultado de la resta debe interpretarse como un entero de 16 bits con signo.
        
    ``` Si el resultado es negativo, la información recién recibida es
        considerada más antigua que la información existente y, por lo tanto, obsoleta
        y redundante y, por lo tanto, DEBE descartarse.
        
        Si el resultado es positivo, la información recién recibida es más nueva
        que la información existente y no se considera obsoleta o
        redundante y DEBE ser procesado.

        Si el resultado es cero, la información recién recibida no es
         considerado obsoleto y, por lo tanto, DEBE procesarse más en caso de que
        la nueva información ofrece una mejor ruta (ver Sección 6.7.1 y
        Sección 6.8).
        
    ```

  Junto con el algoritmo en la Sección 6.7.1, manteniendo un orden temporal se garantiza la libertad del bucle.

   Un enrutador AODVv2 DEBE mantener su número de secuencia en almacenamiento persistente. 
   En los enrutadores que no se pueden almacenar el estado persistente de AODVv2,
   la recuperación puede imponer una penalización de rendimiento (por ejemplo, en el caso de AODVv2 reinicio del enrutador), 
   ya que si un enrutador pierde su número de secuencia, hay
   un retraso (por defecto, del orden de minutos) antes de que el enrutador pueda
   reanudar las operaciones completas. Si se pierde el número de secuencia, el enrutador
   DEBE seguir el procedimiento en la Sección 6.1 para reanudar de forma segura las operaciones de enrutamiento
   con un nuevo número de secuencia.

# 4.5. Conjunto de routers locales

   Todos los enrutadores AODVv2 DEBEN mantener un conjunto de rutas locales que contenga
   información obtenida de los mensajes de ruta AODVv2. en El conjunto de routers locales
   se puede considerar almacenar por separado la tabla de enrutamiento del plano de reenvío
   (denominada Base de información de enrutamiento (RIB)), el cual puede ser actualizado por otros protocolos 
   de enrutamiento que operan tambien en el enrutador AODVv2. 
   La base de información de enrutamiento se actualiza utilizando información del conjunto de rutas locales. 
   Alternativamente, si la información especificada a continuación se puede agregar a las entradas RIB,
   las implementaciones PUEDEN elegir modificar la Base de información de enrutamiento
   directamente en lugar de mantener un conjunto dedicado de rutas locales. En esto
   caso, ya que se accede a la entrada de la tabla de ruta cada vez que  un paquete usa el router, 
   el campo **LastUsed** (ver abajo) se puede probar para determinar
   el estado del router, incluso si el tiempo de la ruta ha expirado 
   Por ejemplo, si CurrentTime es menor que 
   ```LocalRoute.LastUsed + ACTIVE_INTERVAL + MAX_IDLETIME```, 
   
   una ruta válida todavía se puede utilizar para
   reenviar el paquete. De lo contrario, la ruta ha expirado y el
   El estado de la ruta DEBE cambiarse para que sea inválida.
   
   
   Cuando este método de gestión de tiempos de espera de ruta se puede utilizar, 
   AODVv2 no lo hace de otra manera requieren la implementación para mantener una interrupción del temporizador. Esto puede
   ser considerado un método "a pedido" para gestionar tiempo de expiracion de los routers.

Las rutas obtenidas por el enrutador de mensages AODVv2 son referenciadas en este documento como LocalRoutes o rutas locales,
y deben contener la siguiente informacion.

  **LocalRoute.Address**  
    Una dirección que, cuando se combina con LocalRoute.PrefixLength,
    describe el conjunto de direcciones de destino para las cuales esta ruta
    permite reenvío.

   **LocalRoute.PrefixLength**
      La longitud del prefijo, en bits, asociada con LocalRoute.Address.

   **LocalRoute.SeqNum**
      El número de secuencia asociado con LocalRoute.Address, obtenido
      desde el último mensaje de ruta que actualizó con éxito esta entrada.

   **LocalRoute.NextHop**
      La dirección IP de origen del paquete IP que contiene el mensaje AODVv2
      que anuncia la ruta a LocalRoute.Address, es decir, una direccion IP
      del enrutador AODVv2 utilizado para el siguiente salto en la ruta
      hacia LocalRoute.Address.

   **LocalRoute.NextHopInterface**
      La interfaz utilizada para enviar paquetes IP hacia LocalRoute.Address.

   **LocalRoute.LastUsed**
      Si esta ruta está instalada en la Base de información de enrutamiento,
      el tiempo en el que se uso la ultima vez para reenviar un paquete IP. Si no, el tiempo
      en el que se creó LocalRoute.
    

   **LocalRoute.LastSeqNumUpdate**
      La hora en que LocalRoute.SeqNum se actualizó por última vez.

   **LocalRoute.MetricType**
      El tipo de métrica asociada a esta ruta. Ver la Sección 5 para
      información sobre el manejo de AODVv2 de múltiples tipos de métricas.

   **LocalRoute.Metric**
      El costo de la ruta hacia LocalRoute. Dirección expresada en unidades
      consistente con LocalRoute.MetricType.

   **LocalRoute.Precursors (característica opcional)**
      Una lista de vecinos aguas arriba que usan la ruta (ver Sección 10).

   **LocalRoute.SeqNoRtr**
      Si no es cero, la dirección IP del enrutador que originó el
      Número de secuencia para esta ruta.

   **LocalRoute.State**
      El último estado conocido (no confirmado, inactivo, activo o no válido) de
      la ruta.

   ## Hay cuatro estados posibles para un LocalRoute:

    - No confirmado
        Una ruta obtenida de un mensaje de Solicitud de ruta, que aún no ha sido
        confirmado como bidireccional. NO DEBE almacenarse en la RIB
        para reenviar el tráfico general del plano de datos, pero se puede usar para
        transmitir paquetes RREP junto con una solicitud de verificacion de enlace bidireccional.
        Una ruta no confirmada no se considera una ruta válida.
        Este estado solo se usa para rutas obtenidas a través de
        Mensajes RREQ.

   - Idle (Ocioso)
      Una ruta que se ha confirmado que es bidireccional, pero no ha
      sido utilizada en el último ACTIVE_INTERVAL. Se puede usar para
      reenviar paquetes IP y, por lo tanto, se considera ruta valida.

   Activo
      Una ruta válida que se ha utilizado para reenviar paquetes IP durante
      el último ACTIVE_INTERVAL.

   Inválido
      Una ruta que ha expirado o se ha roto. NO DEBE usarse para
      reenvío de paquetes IP. Las rutas inválidas contienen el numero de secuencia del destino,
    que puede ser útil al evaluar la frescura de la información de enrutamiento entrante.

   Si el conjunto de rutas locales se almacenan por separado de la RIB, las rutas
   se agregan a la RIB cuando LocalRoute.State se activa y
   eliminado del RIB cuando LocalRoute.State se vuelve inválido. Cambios
   al estado de LocalRoute se detallan en la Sección 6.10.1.

# 4.6. Conjunto de mensajes de multidifusión

   Los mensajes RREQ de multidifusión DEBEN ser probados por redundancia para evitar
   procesamiento y reenvío innecesarios.

   El conjunto de mensajes de multidifusión RREQ es un conjunto conceptual que contiene
   información sobre mensajes de multidifusión recibidos anteriormente, de modo que
   los mensajes entrantes se pueden comparar con los mensajes recibidos previamente
   para determinar si la información entrante es redundante u obsoleta, entonces
   que el enrutador puede evitar enviar tráfico de control redundante.

   Las entradas del conjunto de mensajes de multidifusión contienen la siguiente información:

   **McMsg.OrigPrefix**
      El prefijo asociado con OrigAddr, la dirección de origen del paquete IP que activa el RREQ.

   **McMsg.OrigPrefixLen**
    La longitud del prefijo asociada con McMsg.OrigPrefix, 
    desde Router Client Establezca la entrada en RREQ_Gen que incluye OrigAddr.

   **McMsg.TargPrefix**
      El prefijo asociado con TargAddr, la dirección de destino de
      El paquete IP que activa la solicitud de ruta. En un RREQ esto DEBE
      establecerse en TargAddr.

   **McMsg.OrigSeqNum**
      El número de secuencia asociado con la ruta a OrigPrefix, si
      RteMsg es un RREQ.

   **McMsg.TargSeqNum**
      El número de secuencia asociado con la ruta a TargPrefix.

   **McMsg.MetricType**
      El tipo de métrica de la ruta solicitada.

   **McMsg.Metric**
      El valor métrico recibido en el RteMsg.

   **McMsg.Timestamp**
      La última vez que se actualizó esta entrada del conjunto de mensajes de multidifusión.

   **McMsg.RemovalTime**
      La hora a la que esta entrada DEBE eliminarse del conjunti de mensajes de ruta de multidifusión.

   **McMsg.Interfaz**
      La interfaz en la que se recibió el mensaje.

   **McMsg.SeqNoRtr**
      Si no es cero, la dirección IP del enrutador que originó el
      Número de secuencia para esta ruta.

   El conjunto de mensajes de multidifusión se mantiene para que dos entradas no tengan
   los mismos OrigPrefix, OrigPrefixLen, TargPrefix y MetricType. Ver
   Sección 6.8 para detalles sobre la actualización de este conjunto.

# 4.7. Error de ruta (RERR) establecida

   Cada mensaje RERR enviado porque no existe una ruta para el reenvío de paquetes.
   DEBE registrarse en un conjunto conceptual llamado conjunto de error de ruta (RERR). 
   Cada entrada contiene la siguiente información:

   **RerrMsg.Timeout**
      El tiempo después del cual la entrada DEBE ser eliminada.

   **RerrMsg.UnreachableAddress**
      La UnreachableAddress reportada en la AddressList de la RERR.

   **RerrMsg.PktSource**
      El PktSource del RERR (ver Sección 2).

   Consulte la Sección 6.9 para obtener instrucciones sobre cómo actualizar el conjunto.

# 5. Métricas

   Las métricas miden un costo o calidad asociado con una ruta o un enlace,
   por ejemplo, latencia, demora, costo financiero, energía, etc. Los valores métricos son
   informados en los mensajes de solicitud de ruta y respuesta de ruta.

   En los mensajes de solicitud de ruta, la métrica describe el costo de la ruta
   desde OrigPrefix al enrutador que transmite la solicitud de ruta. para RREQ_Gen, 
   este es el costo asociado con el conjunto de entradas de clientes de enrutador la cual incluye OrigAddr. 
   
   Para los enrutadores que reenvían el RREQ,Este es el costo de OrigPrefix para el enrutador de reenvío, combinando
   El valor métrico del mensaje RREQ recibido con el conocimiento de
   costo de enlace del remitente al receptor, es decir, el costo del enlace entrante. 
   Este costo de ruta actualizado se incluye al reenviar el mensaje de solicitud de ruta, 
   y se utiliza para instalar una ruta a OrigPrefix.

   Del mismo modo, en los mensajes de respuesta de ruta, la métrica refleja el costo de
   la ruta desde TargPrefix al enrutador que transmite la Respuesta de ruta.
   Para RREP_Gen, este es el costo asociado con el conjunto de entradas de clientes de enrutador
   que incluye TargAddr. 
   Para los enrutadores que reenvían el RREP,
   Este es el costo de TargPrefix para el enrutador de reenvío, combinando
   El valor métrico del mensaje RREP recibido con conocimiento del
   costo de enlace del remitente al receptor, es decir, el costo del enlace entrante. 
   Este costo de ruta actualizado se incluye al reenviar el mensaje de respuesta de ruta, 
   y se utiliza para instalar una ruta a TargPrefix.

   Cuando las métricas de enlace son simétricas, el costo de las rutas instaladas en
   La ruta local establecida en cada enrutador será correcta. Esta suposición
   a menudo es inexacto, pero calcular datos métricos entrantes / salientes esta
   fuera del alcance de este documento. La ruta descubierta es buena para
   el enrutador solicitante, pero la ruta de retorno puede no ser la ruta óptima.

   AODVv2 permite el uso de múltiples tipos de métricas. Cada intento de descubrimiento de ruta 
   indica el tipo de métrica que se solicita para la ruta. 
   Pueden existir múltiples rutas válidas en el conjunto de rutas locales
   para la misma dirección y longitud del prefijo pero para diferentes tipos de métricas. 
   Más de una ruta a una dirección particular y longitud de prefijo
   NO DEBE existir en la Base de información de enrutamiento a menos que cada paquete pueda
   ser inspeccionado para determinar qué ruta en el RIB tiene el tipo de metrica adecuado
    según se requiera para ese paquete. De lo contrario, solo una ruta
   a la vez a una dirección particular y la longitud del prefijo puede existir en la RIB.
   El algoritmo utilizado para inspeccionar el paquete y determinar sobre qué rutas deben instalarse en la
   base de información de enrutamiento, está fuera del alcance de AODVv2.

   ## Para cada MetricType, AODVv2 requiere:

   o Un número de MetricType, para indicar el tipo de métrica de una ruta.
      Los números de MetricType asignados actualmente se enumeran en la Sección 13.4.

   o Un valor máximo, denotado MAX_METRIC [MetricType]. Esto DEBE siempre
      ser el valor métrico máximo expresable de tipo MetricType. Los campos de 
      longitudes asociadas con los valores métricos se encuentran en la Sección 13.4.
      Si el costo de una ruta excede MAX_METRIC [MetricType], la ruta
      no se puede almacenar y se ignora.

   o Una función para el costo del enlace entrante, denominado Costo (L). Utilizando
      los costos del enlace entrante significan que la ruta obtenida tiene una métrica
      precisa para la dirección hacia el enrutador de origen.

   o Una función para el costo de la ruta, denotada Costo (R).

   o Una función para analizar rutas para posibles bucles basados ​​en informacion de métrica, 
   denominada LoopFree (R1, R2). LoopFree verifica que 
      la ruta R2 no es una subsección de otra ruta R1. 
      Un router AODVv2 invoca LoopFree () como parte del proceso en la Sección 6.7.1,
      cuando una ruta anunciada (R1) y una ruta local existente (R2) tienen
      la misma dirección de destino, tipo de métrica y número de secuencia.
      LoopFree devuelve FALSE para indicar que una ruta anunciada no es
      para usarse para actualizar un LocalRoute almacenado, ya que puede causar un
      bucle de enrutamiento. En el caso donde el LocalRoute existente es
      No es válido, es posible que la ruta anunciada incluya el
      LocalRoute existente y proviene de un enrutador que aún no
      recibe notificación de que la ruta no es válida, por lo que
      la ruta anunciada no debe usarse para actualizar el conjunto de rutas locales,
      en caso de que forme un bucle a una ruta rota.

   AODVv2 actualmente admite métricas de costos donde Cost (R) es estrictamente
   aumentando, definiendo:

   o Costo (R): = Suma del costo (L) de cada enlace en la ruta

   o LoopFree (R1, R2): = (Costo (R1) <= Costo (R2))

   Los implementadores PUEDEN considerar los tipos de indicadores que no son estrictamente
   aumentando, pero las definiciones de las funciones Cost y LoopFree para
