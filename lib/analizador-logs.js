// lib/analizador-logs.js - Módulo completo de análisis de logs Apache
const fs = require('fs').promises;
const zlib = require('zlib');
const { promisify } = require('util');
const https = require('https');
const http = require('http');
const { DOMParser } = require('xmldom');

const gunzip = promisify(zlib.gunzip);

class AnalizadorLogs {
  constructor() {
    this.datos = [];
    this.estadisticas = {};
    this.urlsSitemap = [];
    this.analisisSitemap = null;
  }

  // Función principal para procesar archivo y sitemap
  async procesarAnalisisCompleto(rutaArchivo, urlSitemap = null) {
    try {
      console.log('Iniciando análisis completo de logs...');
      
      // Paso 1: Leer y parsear archivo de logs
      console.log('Paso 1: Procesando archivo de logs...');
      const contenido = await this.leerArchivo(rutaArchivo);
      await this.parsearContenidoLogs(contenido);
      
      // Paso 2: Procesar sitemap si se proporciona
      if (urlSitemap) {
        console.log('Paso 2: Procesando sitemap...');
        try {
          await this.procesarSitemap(urlSitemap);
        } catch (error) {
          console.warn('Error procesando sitemap:', error.message);
          this.urlsSitemap = [];
        }
      }
      
      // Paso 3: Analizar datos
      console.log('Paso 3: Analizando datos...');
      this.analizarDatos();
      
      // Paso 4: Limpiar archivo temporal
      await fs.unlink(rutaArchivo).catch(() => {});
      
      console.log('Análisis completado exitosamente');
      return this.obtenerResultados();
      
    } catch (error) {
      console.error('Error en análisis completo:', error);
      throw new Error(`Error procesando análisis: ${error.message}`);
    }
  }

  // Leer archivo (normal o comprimido)
  async leerArchivo(rutaArchivo) {
    try {
      if (rutaArchivo.endsWith('.gz')) {
        const compressed = await fs.readFile(rutaArchivo);
        const decompressed = await gunzip(compressed);
        return decompressed.toString('utf8');
      } else {
        return await fs.readFile(rutaArchivo, 'utf8');
      }
    } catch (error) {
      throw new Error(`Error leyendo archivo: ${error.message}`);
    }
  }

  // Parsear contenido de logs Apache
  async parsearContenidoLogs(contenido) {
    const lineas = contenido.split('\n').filter(linea => linea.trim());
    
    // Regex para Apache Combined Log Format
    const regexLog = /^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (.*?) (\S+)" (\d+) (\S+) "(.*?)" "(.*?)"$/;
    
    this.datos = [];
    console.log(`Procesando ${lineas.length} líneas de log...`);
    
    for (let i = 0; i < lineas.length; i++) {
      const linea = lineas[i];
      const coincidencia = linea.match(regexLog);
      
      if (coincidencia) {
        const [, ip, timestamp, metodo, url, protocolo, estado, tamano, referer, userAgent] = coincidencia;
        
        const entrada = {
          ip,
          timestamp: this.parsearTimestampApache(timestamp),
          metodo,
          url: this.normalizarUrl(this.construirUrlCompleta(url)),
          protocolo,
          estado: parseInt(estado),
          tamano: tamano === '-' ? 0 : parseInt(tamano),
          referer,
          userAgent,
          esBot: this.esBot(userAgent),
          nombreBot: this.esBot(userAgent) ? this.obtenerNombreBot(userAgent) : null
        };
        
        this.datos.push(entrada);
      }
      
      // Progreso cada 1000 líneas
      if (i % 1000 === 0 && i > 0) {
        console.log(`Procesadas ${i} líneas...`);
      }
    }
    
    console.log(`Total de entradas procesadas: ${this.datos.length}`);
  }

  // Procesar sitemap desde URL
  async procesarSitemap(urlSitemap) {
    try {
      console.log(`Descargando sitemap: ${urlSitemap}`);
      const contenidoXml = await this.descargarSitemap(urlSitemap);
      this.urlsSitemap = this.parsearSitemap(contenidoXml);
      console.log(`Sitemap procesado: ${this.urlsSitemap.length} URLs encontradas`);
    } catch (error) {
      throw new Error(`Error procesando sitemap: ${error.message}`);
    }
  }

  // Descargar sitemap
  descargarSitemap(url) {
    return new Promise((resolve, reject) => {
      const cliente = url.startsWith('https:') ? https : http;
      
      const timeout = setTimeout(() => {
        reject(new Error('Timeout descargando sitemap (30s)'));
      }, 30000);
      
      cliente.get(url, {
        headers: {
          'User-Agent': 'Analizador-Logs-SEO/1.0'
        }
      }, (respuesta) => {
        clearTimeout(timeout);
        
        if (respuesta.statusCode !== 200) {
          reject(new Error(`Error HTTP ${respuesta.statusCode}: ${respuesta.statusMessage}`));
          return;
        }
        
        let datos = '';
        respuesta.on('data', (chunk) => datos += chunk);
        respuesta.on('end', () => resolve(datos));
        respuesta.on('error', reject);
      }).on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  // Parsear XML del sitemap
  parsearSitemap(contenidoXml) {
    const urls = [];
    const maxUrls = 15000; // Límite para evitar sobrecarga
    
    try {
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(contenidoXml, 'text/xml');
      
      // Verificar errores de parsing
      const errorNode = xmlDoc.getElementsByTagName('parsererror')[0];
      if (errorNode) {
        throw new Error('XML malformado en sitemap');
      }
      
      // Detectar tipo de sitemap
      const elementosSitemap = xmlDoc.getElementsByTagName('sitemap');
      const elementosUrl = xmlDoc.getElementsByTagName('url');
      
      if (elementosSitemap.length > 0) {
        console.warn('Sitemap index detectado. Solo se procesará el primer nivel.');
      }
      
      if (elementosUrl.length > 0) {
        for (let i = 0; i < Math.min(elementosUrl.length, maxUrls); i++) {
          const elementoLoc = elementosUrl[i].getElementsByTagName('loc')[0];
          if (elementoLoc && elementoLoc.textContent) {
            urls.push(this.normalizarUrl(elementoLoc.textContent.trim()));
          }
        }
      }
      
      if (urls.length === maxUrls) {
        console.warn(`Límite de ${maxUrls} URLs alcanzado en sitemap`);
      }
      
    } catch (error) {
      throw new Error(`Error parseando sitemap XML: ${error.message}`);
    }
    
    return urls;
  }

  // Analizar todos los datos
  analizarDatos() {
    console.log('Iniciando análisis detallado de datos...');
    
    const totalPeticiones = this.datos.length;
    const peticionesBots = this.datos.filter(entrada => entrada.esBot).length;
    const peticionesHumanos = totalPeticiones - peticionesBots;
    
    // Análisis básico
    const codigosEstado = {};
    const datosPorHora = {};
    const estadisticasUrl = {};
    const estadisticasBots = {};
    const estadisticasErrores = {};
    const datosPorDia = {};
    
    console.log('Analizando patrones de acceso...');
    
    this.datos.forEach(entrada => {
      // Códigos de estado
      codigosEstado[entrada.estado] = (codigosEstado[entrada.estado] || 0) + 1;
      
      // Análisis por horas
      const hora = entrada.timestamp.getHours();
      datosPorHora[hora] = (datosPorHora[hora] || 0) + 1;
      
      // Análisis por días
      const fecha = entrada.timestamp.toISOString().split('T')[0];
      if (entrada.esBot) {
        datosPorDia[fecha] = (datosPorDia[fecha] || 0) + 1;
      }
      
      // Análisis de URLs
      if (!estadisticasUrl[entrada.url]) {
        estadisticasUrl[entrada.url] = {
          conteo: 0,
          tamanoTotal: 0,
          estados: {},
          ultimaVista: entrada.timestamp,
          crawleadaPorBots: 0,
          botsUnicos: new Set(),
          tiempoRespuestaTotal: 0,
          enSitemap: this.urlsSitemap.length > 0 ? this.urlsSitemap.includes(entrada.url) : null
        };
      }
      
      const statsUrl = estadisticasUrl[entrada.url];
      statsUrl.conteo++;
      statsUrl.tamanoTotal += entrada.tamano;
      statsUrl.estados[entrada.estado] = (statsUrl.estados[entrada.estado] || 0) + 1;
      
      if (entrada.timestamp > statsUrl.ultimaVista) {
        statsUrl.ultimaVista = entrada.timestamp;
      }
      
      if (entrada.esBot) {
        statsUrl.crawleadaPorBots++;
        statsUrl.botsUnicos.add(entrada.nombreBot);
      }
      
      // Análisis de bots
      if (entrada.esBot) {
        const nombreBot = entrada.nombreBot;
        if (!estadisticasBots[nombreBot]) {
          estadisticasBots[nombreBot] = {
            conteo: 0,
            tamanoTotal: 0,
            urlsUnicas: new Set(),
            peticionesPorDia: {}
          };
        }
        
        estadisticasBots[nombreBot].conteo++;
        estadisticasBots[nombreBot].tamanoTotal += entrada.tamano;
        estadisticasBots[nombreBot].urlsUnicas.add(entrada.url);
        estadisticasBots[nombreBot].peticionesPorDia[fecha] = 
          (estadisticasBots[nombreBot].peticionesPorDia[fecha] || 0) + 1;
      }
      
      // Análisis de errores
      if (entrada.estado >= 400) {
        const claveError = `${entrada.url}:${entrada.estado}`;
        if (!estadisticasErrores[claveError]) {
          estadisticasErrores[claveError] = {
            url: entrada.url,
            estado: entrada.estado,
            conteo: 0,
            ultimaVista: entrada.timestamp
          };
        }
        estadisticasErrores[claveError].conteo++;
        if (entrada.timestamp > estadisticasErrores[claveError].ultimaVista) {
          estadisticasErrores[claveError].ultimaVista = entrada.timestamp;
        }
      }
    });
    
    console.log('Analizando directorios y patrones...');
    
    // Análisis de directorios
    const estadisticasDirectorios = this.analizarDirectorios();
    
    // Análisis comparativo con sitemap
    let analisisSitemap = null;
    if (this.urlsSitemap.length > 0) {
      analisisSitemap = this.analizarSitemapVsCrawleadas(estadisticasUrl);
    }
    
    // Convertir Sets a arrays para serialización
    Object.values(estadisticasUrl).forEach(stat => {
      stat.botsUnicos = Array.from(stat.botsUnicos);
    });
    
    Object.values(estadisticasBots).forEach(stat => {
      stat.urlsUnicas = Array.from(stat.urlsUnicas);
    });
    
    // Guardar estadísticas completas
    this.estadisticas = {
      totalPeticiones,
      peticionesBots,
      peticionesHumanos,
      codigosEstado,
      datosPorHora,
      estadisticasUrl,
      estadisticasBots,
      estadisticasErrores,
      estadisticasDirectorios,
      datosPorDia,
      analisisSitemap,
      tamanoTotal: this.datos.reduce((sum, entrada) => sum + entrada.tamano, 0),
      rangoTiempo: {
        inicio: new Date(Math.min(...this.datos.map(entrada => entrada.timestamp))),
        fin: new Date(Math.max(...this.datos.map(entrada => entrada.timestamp)))
      },
      procesadoEn: new Date().toISOString()
    };
    
    console.log('Análisis de datos completado');
  }

  // Análisis por directorios
  analizarDirectorios() {
    const statsDirectorio = {};
    
    this.datos.forEach(entrada => {
      try {
        const url = new URL(entrada.url);
        const partesRuta = url.pathname.split('/').filter(parte => parte.length > 0);
        const directorio = partesRuta.length > 0 ? '/' + partesRuta[0] + '/' : '/';
        
        if (!statsDirectorio[directorio]) {
          statsDirectorio[directorio] = {
            totalPeticiones: 0,
            peticionesBots: 0,
            urlsUnicas: new Set(),
            tiempoRespuestaTotal: 0,
            tamanoTotal: 0,
            errores: 0
          };
        }
        
        const stats = statsDirectorio[directorio];
        stats.totalPeticiones++;
        stats.urlsUnicas.add(entrada.url);
        stats.tamanoTotal += entrada.tamano;
        
        if (entrada.esBot) {
          stats.peticionesBots++;
        }
        
        if (entrada.estado >= 400) {
          stats.errores++;
        }
        
      } catch (error) {
        // Ignorar URLs malformadas
      }
    });
    
    // Convertir Sets a números
    Object.values(statsDirectorio).forEach(stat => {
      stat.urlsUnicas = stat.urlsUnicas.size;
    });
    
    return statsDirectorio;
  }

  // Análisis comparativo sitemap vs crawleadas
  analizarSitemapVsCrawleadas(estadisticasUrl) {
    const urlsCrawleadas = new Set(Object.keys(estadisticasUrl));
    const urlsSitemapSet = new Set(this.urlsSitemap);
    
    const enAmbos = this.urlsSitemap.filter(url => urlsCrawleadas.has(url));
    const enSitemapNoCrawleadas = this.urlsSitemap.filter(url => !urlsCrawleadas.has(url));
    const crawleadasNoEnSitemap = Array.from(urlsCrawleadas).filter(url => !urlsSitemapSet.has(url));
    
    return {
      totalUrlsSitemap: this.urlsSitemap.length,
      totalUrlsCrawleadas: urlsCrawleadas.size,
      enAmbos: enAmbos.length,
      enSitemapNoCrawleadas: enSitemapNoCrawleadas.length,
      crawleadasNoEnSitemap: crawleadasNoEnSitemap.length,
      listaEnSitemapNoCrawleadas: enSitemapNoCrawleadas,
      listaCrawleadasNoEnSitemap: crawleadasNoEnSitemap,
      porcentajeCobertura: this.urlsSitemap.length > 0 ? 
        ((enAmbos.length / this.urlsSitemap.length) * 100).toFixed(1) : 0
    };
  }

  // Funciones de utilidad
  parsearTimestampApache(timestamp) {
    const mapasMeses = {
      'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
      'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
      'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
    };
    
    const match = timestamp.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/);
    if (match) {
      const [, dia, mes, ano, hora, minuto, segundo] = match;
      const numeroMes = mapasMeses[mes];
      if (numeroMes) {
        return new Date(`${ano}-${numeroMes}-${dia}T${hora}:${minuto}:${segundo}`);
      }
    }
    return new Date();
  }

  construirUrlCompleta(ruta) {
    if (ruta.startsWith('http://') || ruta.startsWith('https://')) {
      return ruta;
    }
    return `https://ejemplo.com${ruta}`; // Placeholder, se puede mejorar
  }

  normalizarUrl(url) {
    try {
      const urlObj = new URL(url);
      urlObj.hash = '';
      const params = Array.from(urlObj.searchParams.entries())
        .sort()
        .map(([key, value]) => `${key}=${value}`)
        .join('&');
      urlObj.search = params ? '?' + params : '';
      return urlObj.toString();
    } catch {
      return url;
    }
  }

  esBot(userAgent) {
    const patronesBots = [
      /googlebot/i, /bingbot/i, /petalbot/i, /yandexbot/i, /duckduckbot/i,
      /baiduspider/i, /facebookexternalhit/i, /twitterbot/i, /linkedinbot/i,
      /screaming frog/i, /semrushbot/i, /ahrefsbot/i, /mj12bot/i,
      /uptimerobot/i, /pingdom/i, /gtmetrix/i, /curl/i, /wget/i,
      /applebot/i, /slurp/i, /dotbot/i, /ia_archiver/i,
      /bot|crawler|spider|scraper|fetch|monitor/i
    ];
    
    return patronesBots.some(patron => patron.test(userAgent));
  }

  obtenerNombreBot(userAgent) {
    if (/googlebot-image/i.test(userAgent)) return 'Googlebot Imágenes';
    if (/googlebot-news/i.test(userAgent)) return 'Googlebot Noticias';
    if (/googlebot/i.test(userAgent)) return 'Googlebot';
    if (/bingbot/i.test(userAgent)) return 'Bingbot';
    if (/petalbot/i.test(userAgent)) return 'PetalBot';
    if (/yandexbot/i.test(userAgent)) return 'YandexBot';
    if (/duckduckbot/i.test(userAgent)) return 'DuckDuckBot';
    if (/applebot/i.test(userAgent)) return 'Applebot';
    if (/screaming frog/i.test(userAgent)) return 'Screaming Frog';
    if (/semrushbot/i.test(userAgent)) return 'SEMrush Bot';
    if (/ahrefsbot/i.test(userAgent)) return 'Ahrefs Bot';
    if (/facebookexternalhit/i.test(userAgent)) return 'Facebook Bot';
    if (/twitterbot/i.test(userAgent)) return 'Twitter Bot';
    if (/uptimerobot/i.test(userAgent)) return 'UptimeRobot';
    if (/curl/i.test(userAgent)) return 'cURL';
    if (/wget/i.test(userAgent)) return 'Wget';
    if (/dotbot/i.test(userAgent)) return 'DotBot';
    if (/bot|crawler|spider/i.test(userAgent)) return 'Bot Genérico';
    
    return 'Bot Desconocido';
  }

  // Obtener resultados finales
  obtenerResultados() {
    return {
      exito: true,
      estadisticas: this.estadisticas,
      resumen: {
        totalPeticiones: this.estadisticas.totalPeticiones,
        peticionesBots: this.estadisticas.peticionesBots,
        porcentajeBots: ((this.estadisticas.peticionesBots / this.estadisticas.totalPeticiones) * 100).toFixed(1),
        urlsUnicas: Object.keys(this.estadisticas.estadisticasUrl).length,
        erroresDetectados: Object.keys(this.estadisticas.estadisticasErrores).length,
        tamanoTotalMB: (this.estadisticas.tamanoTotal / 1024 / 1024).toFixed(2),
        urlsSitemap: this.urlsSitemap.length,
        periodoAnalisis: {
          desde: this.estadisticas.rangoTiempo.inicio.toISOString(),
          hasta: this.estadisticas.rangoTiempo.fin.toISOString()
        }
      }
    };
  }

  // Obtener estadísticas para gráficos
  obtenerDatosGraficos() {
    const stats = this.estadisticas;
    
    return {
      codigosEstado: Object.entries(stats.codigosEstado)
        .map(([codigo, conteo]) => ({ codigo: parseInt(codigo), conteo }))
        .sort((a, b) => a.codigo - b.codigo),
      
      distribucionBots: [
        { tipo: 'Bots', conteo: stats.peticionesBots },
        { tipo: 'Humanos', conteo: stats.peticionesHumanos }
      ],
      
      actividadPorHora: Array.from({length: 24}, (_, i) => ({
        hora: i,
        peticiones: stats.datosPorHora[i] || 0
      })),
      
      topBots: Object.entries(stats.estadisticasBots)
        .sort(([,a], [,b]) => b.conteo - a.conteo)
        .slice(0, 10)
        .map(([nombre, datos]) => ({
          nombre,
          peticiones: datos.conteo,
          urlsUnicas: datos.urlsUnicas.length,
          porcentaje: ((datos.conteo / stats.totalPeticiones) * 100).toFixed(1)
        })),
      
      topUrls: Object.entries(stats.estadisticasUrl)
        .sort(([,a], [,b]) => b.conteo - a.conteo)
        .slice(0, 20)
        .map(([url, datos]) => ({
          url,
          visitas: datos.conteo,
          crawleadaPorBots: datos.crawleadaPorBots,
          botsUnicos: datos.botsUnicos.length,
          tamanoPromedio: Math.round(datos.tamanoTotal / datos.conteo),
          enSitemap: datos.enSitemap
        }))
    };
  }
}

module.exports = AnalizadorLogs;
