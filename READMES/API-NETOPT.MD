# API NETOPT

Esta interfaz proporciona una API uniforme para que las pilas de red interactúen con los controladores de dispositivos de red. Esta interfaz está diseñada de una manera que es completamente independiente de la pila de red utilizada. De esta forma, los controladores de dispositivos para dispositivos de red (por ejemplo, radios IEEE802.15.4, dispositivos Ethernet, ...) deben implementarse una vez y pueden usarse con cualquier pila de red compatible en RIOT.

Las funciones proporcionadas por la interfaz cubren tres partes principales:

- envío y recepción de datos de red reales
- configuración del dispositivo de red a través de la lectura y configuración de parámetros del dispositivo
- manejo de eventos.



# El problema del contexto de interrupción

Los dispositivos de red generalmente están conectados a la CPU del host a través de algún tipo de bus, más comúnmente a través de SPI. Este tipo de conexión tiene la desventaja de que el bus no es utilizado solo por el dispositivo de red, sino que puede compartirse con otros dispositivos. Esto hace que sea necesario sincronizar el acceso al bus para evitar colisiones de acceso al bus.

Para ilustrar este comportamiento, veamos una situación de error típica, que conduce a una falla latente muy difícil de encontrar y depurar: digamos que tenemos dos dispositivos A y B en el mismo bus SPI. Nuestra CPU ahora está transfiriendo una porción de 100 bytes al dispositivo A. Después de que se transfirieron 20 bytes, el dispositivo B activa una interrupción externa en la CPU del host. El manejo de interrupciones ahora generalmente requiere la lectura de algún tipo de registro de estado en el dispositivo "disparador", dispositivo B en este caso. Entonces, lo que sucedería aquí, es que el controlador de dispositivo para el dispositivo B iniciaría una nueva transferencia SPI en el bus ya utilizado para leer el registro de estado de B -> BAM.

Los controladores periféricos para los buses compartidos (es decir, SPI e I2C) implementan la sincronización de acceso mediante mutexes, que se bloquean y desbloquean en las funciones requeridas y liberadas del controlador. El problema ahora es que este tipo de sincronización solo funciona en contexto de subproceso, pero no en contexto de interrupción. Con un esfuerzo razonable y el uso de recursos, no tenemos medios para sincronizar el acceso al bus también en un contexto de interrupción.

La solución a este problema implementado por esta interfaz es no llamar a ninguna función que interactúe con un dispositivo directamente desde el contexto de interrupción. Desafortunadamente, esto requiere cierta complejidad adicional para los esfuerzos de sincronización entre el hilo y el contexto de interrupción para poder manejar eventos del dispositivo (es decir, interrupciones externas). Vea la sección para más información.


# Requisitos de contexto

La interfaz netdev espera que los controladores de dispositivos de red se ejecuten en contexto de subproceso (consulte la sección anterior). Sin embargo, la interfaz se diseñó de alguna manera, para permitir ser atendido más de un controlador de dispositivo en el mismo hilo.

El elemento de diseño clave para **netdev** es que los controladores de dispositivos que implementan esta interfaz no pueden ejecutarse de forma independiente en un hilo, pero necesitan un código de arranque. Este código de arranque puede ser cualquier cosa, desde un simple bucle msg.h :: msg_receive () (como se hizo para la adaptación de GNRC) a una pila de red completa que funciona sin mensajes por completo, pero se basa en interfaces de llamada de función.

# Enviar y recibir

El envío de datos utilizando la interfaz netdev es sencillo: simplemente llame la funcion del  controlador **netdev.h::netdev_driver::send**, pasándole los datos que deben enviarse. El llamador de la función **netdev.h::netdev_driver::send** (por ejemplo, una pila de red) debe asegurarse de que los datos estén en el formato correcto esperado por el controlador de dispositivo de red específico. Por lo general, los datos deben contener un encabezado de capa de enlace precargado como, p. un IEEE802.15.4 o encabezado Ethernet.

Recibir datos usando la interfaz netdev requiere típicamente cuatro pasos:

1. espere un evento 
```bash 
netdev.h::netdev_event_t::NETDEV_EVENT_RX_COMPLETE
```

2. llame la siguiente funcion para obtener los datos recibidos
```bash
 netdev.h::netdev_driver::recv con buf: = NULL y len: = 0 
```
3. asignar un búfer lo suficientemente grande de alguna manera.
  
4. llame a la función **netdev.h::netdev_driver::recv** por segunda vez, pasando el búfer y leyendo los datos recibidos en este búfer

Por supuesto, esta secuencia de recepción se puede simplificar omitiendo los pasos **2** y **3** cuando se utilizan memorias intermedias preasignadas de tamaño fijo o medios similares.

# Configuración del dispositivo

La interfaz **netdev** cubre una amplia variedad de dispositivos de red, que difieren en cierta medida en sus parámetros de configuración (por ejemplo, radios frente a interfaces cableadas, selección de canales frente a detección de estado de enlace). Para cubrir esta variedad, **netdev** proporciona una interfaz de configuración genérica al exponer funciones simples de **netdev.h::netdev_driver::get** y **netdev.h::netdev_driver::set**. Estos se basan en una lista de opciones ampliable y definida globalmente como se define en netopt.h.

Cada controlador de dispositivo puede elegir las opciones que admite para leer y / o escribir de esta lista. Si el controlador del dispositivo no admite una opción, el controlador simplemente devuelve **ENOTSUP**.