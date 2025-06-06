// Función para inicializar los gráficos
function initCharts() {
    console.log('Inicializando gráficos...');
    
    // Verificar si los elementos del gráfico existen
    const alertTypesCtx = document.getElementById('alertTypesChart');
    const severityCtx = document.getElementById('severityChart');
    
    if (!alertTypesCtx || !severityCtx) {
        console.error('No se encontraron los elementos del gráfico');
        return;
    }
    
    // Debug: mostrar datos en consola
    console.log('Datos disponibles en initCharts:');
    console.log('alertTypesData:', window.alertTypesData);
    console.log('severityData:', window.severityData);
    
    // Verificar si hay datos para mostrar
    if (!window.alertTypesData || !window.alertTypesData.labels || window.alertTypesData.labels.length === 0) {
        console.warn('No hay datos de tipos de alertas para mostrar');
        // Mostrar un mensaje en el contenedor del gráfico
        alertTypesCtx.parentNode.innerHTML += '<p class="no-data">No hay datos disponibles para mostrar</p>';
    } else {
        console.log('Creando gráfico de tipos de alertas con datos:', window.alertTypesData);
        // Destruir el gráfico anterior si existe
        if (alertTypesChart) {
            alertTypesChart.destroy();
        }
        // Gráfico de tipos de alertas
        alertTypesChart = new Chart(alertTypesCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: window.alertTypesData.labels,
                datasets: [{
                    label: 'Número de Alertas',
                    data: window.alertTypesData.data,
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    title: { 
                        display: true, 
                        text: '',
                        font: { size: 16 }
                    }
                },
                scales: {
                    y: { 
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Número de Alertas'
                        }
                    }
                }
            }
        });
    }
    
    // Verificar si hay datos de gravedad para mostrar
    if (!window.severityData || !window.severityData.labels || window.severityData.labels.length === 0) {
        console.warn('No hay datos de gravedad para mostrar');
        // Mostrar un mensaje en el contenedor del gráfico
        if (severityCtx && severityCtx.parentNode) {
            severityCtx.parentNode.innerHTML += '<p class="no-data">No hay datos de gravedad disponibles</p>';
        }
    } else {
        console.log('Creando gráfico de gravedad con datos:', window.severityData);
        // Destruir el gráfico anterior si existe
        if (severityChart) {
            severityChart.destroy();
        }
        
        // Mapa de colores y etiquetas para la gravedad
        const severityConfig = {
            '1': { 
                color: '#00c27e',  // Verde intermedio
                label: 'Baja (1)'
            },
            '2': {
                color: '#ffd600',
                label: 'Media (2)'
            },
            '3': {
                color: '#d50000',
                label: 'Alta (3)'
            },
            '4': {
                color: '#d50000',
                label: 'Crítica (4)'
            }
        };
        
        // Gráfico de distribución de gravedad
        severityChart = new Chart(severityCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: window.severityData.labels,
                datasets: [{
                    data: window.severityData.data,
                    backgroundColor: window.severityData.labels.map((label, index) => {
                        // Usar el índice + 1 como gravedad (1, 2, 3)
                        const severity = (index + 1).toString();
                        return severityConfig[severity]?.color || '#ffd600'; // Amarillo por defecto
                    }),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            color: '#e0e6ed', // Color del texto de la leyenda
                            font: {
                                size: 13,
                                weight: 'bold'
                            },
                            usePointStyle: true,
                            pointStyle: 'circle',
                            padding: 20
                        },
                        title: {
                            display: true,
                            text: 'Niveles de Gravedad',
                            color: '#e0e6ed',
                            padding: { top: 10, bottom: 5 },
                            font: {
                                size: 14,
                                weight: 'bold'
                            }
                        }
                    },
                    title: { 
                        display: true, 
                        text: '', 
                        font: { size: 16 },
                        padding: { bottom: 15 },
                        color: '#e0e6ed' // Color del título para mejor contraste
                    }
                },
                cutout: '70%',
                radius: '90%'
            }
        });
    }
}

// Variables para almacenar las instancias de los gráficos
let alertTypesChart = null;
let severityChart = null;

// Función para destruir los gráficos existentes
function destroyCharts() {
    if (alertTypesChart) {
        alertTypesChart.destroy();
        alertTypesChart = null;
    }
    if (severityChart) {
        severityChart.destroy();
        severityChart = null;
    }
}

// Inicializar los gráficos cuando el DOM esté completamente cargado
document.addEventListener('DOMContentLoaded', function() {
    // Solo inicializar si no estamos en la página de detalles de alerta
    if (!document.getElementById('alertDetails')) {
        console.log('DOM completamente cargado, inicializando gráficos...');
        // Verificar si Chart.js está cargado
        if (typeof Chart === 'undefined') {
            console.error('Chart.js no se ha cargado correctamente');
            return;
        }
        // Destruir gráficos existentes antes de inicializar nuevos
        destroyCharts();
        // Verificar si la función initCharts existe
        if (typeof initCharts === 'function') {
            console.log('Inicializando gráficos...');
            initCharts();
        } else {
            console.error('La función initCharts no está definida');
        }
    }
    if (!window.alertTypesData || !window.severityData) {
        console.error('No se encontraron los datos para los gráficos');
        return;
    }
    
    // Inicializar los gráficos
    initCharts();
});

// Asegurarse de que los gráficos se redimensionen correctamente
window.addEventListener('resize', function() {
    // Re-inicializar los gráficos cuando se redimensione la ventana
    if (typeof initCharts === 'function') {
        initCharts();
    }
});
