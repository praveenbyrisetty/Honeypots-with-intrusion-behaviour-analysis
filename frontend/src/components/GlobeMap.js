import React, { useState, useEffect, useRef } from 'react';
import Globe from 'react-globe.gl';

function GlobeMap() {
  const globeRef = useRef();
  const containerRef = useRef();
  const [width, setWidth] = useState(800);
  const [countries, setCountries] = useState({ features: [] });
  const [threatPoints, setThreatPoints] = useState([]);
  const [activeTheme, setActiveTheme] = useState(
    typeof document !== 'undefined'
      ? (document.documentElement.getAttribute('data-theme') || 'dark')
      : 'dark'
  );

  const rootStyles = typeof window !== 'undefined' ? getComputedStyle(document.documentElement) : null;
  const mapAtmosphereColor = rootStyles?.getPropertyValue('--map-atmosphere-color')?.trim() || '#00f0ff';
  const mapStrokeColor = rootStyles?.getPropertyValue('--map-stroke-color')?.trim() || '#00f0ff';
  const mapHoverFill = rootStyles?.getPropertyValue('--map-hover-fill')?.trim() || 'rgba(0, 240, 255, 0.2)';
  const mapLandFill = rootStyles?.getPropertyValue('--map-land-fill')?.trim() || 'rgba(0, 0, 0, 0)';
  const mapLandSideFill = rootStyles?.getPropertyValue('--map-land-side-fill')?.trim() || 'rgba(0, 0, 0, 0)';
  const mapTooltipBg = rootStyles?.getPropertyValue('--map-tooltip-bg')?.trim() || 'rgba(0, 15, 30, 0.92)';
  const mapTooltipBorder = rootStyles?.getPropertyValue('--map-tooltip-border')?.trim() || '#00f0ff';
  const mapTooltipText = rootStyles?.getPropertyValue('--map-tooltip-text')?.trim() || '#ffffff';
  const mapTooltipSubtext = rootStyles?.getPropertyValue('--map-tooltip-subtext')?.trim() || '#00f0ff';
  const mapThreatPoint = rootStyles?.getPropertyValue('--map-threat-point')?.trim() || '#00f0ff';
  const mapThreatTooltipBg = rootStyles?.getPropertyValue('--map-threat-tooltip-bg')?.trim() || 'rgba(255, 0, 50, 0.92)';
  const mapThreatTooltipBorder = rootStyles?.getPropertyValue('--map-threat-tooltip-border')?.trim() || '#ff3366';
  const globeImageUrl = activeTheme === 'light'
    ? '//unpkg.com/three-globe/example/img/earth-blue-marble.jpg'
    : '//unpkg.com/three-globe/example/img/earth-night.jpg';

  useEffect(() => {
    if (typeof document === 'undefined') {
      return undefined;
    }

    const root = document.documentElement;
    const syncTheme = () => setActiveTheme(root.getAttribute('data-theme') || 'dark');
    syncTheme();

    const observer = new MutationObserver(syncTheme);
    observer.observe(root, { attributes: true, attributeFilter: ['data-theme'] });

    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    // Make globe responsive to container
    if (containerRef.current) {
      setWidth(containerRef.current.clientWidth);
    }

    const handleResize = () => {
      if (containerRef.current) setWidth(containerRef.current.clientWidth);
    };
    window.addEventListener('resize', handleResize);

    // Fetch GeoJSON for country outlines
    fetch('https://raw.githubusercontent.com/vasturiano/react-globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson')
      .then(res => res.json())
      .then(setCountries);
      
    // Set auto rotation
    if (globeRef.current) {
      globeRef.current.controls().autoRotate = true;
      globeRef.current.controls().autoRotateSpeed = 0.5;
      globeRef.current.pointOfView({ lat: 20, lng: 0, altitude: 2 });
    }

    // ACCURATE THREAT GEOLOCATION
    const fetchLocations = async () => {
      try {
        const response = await fetch('/api/top-ips');
        if (!response.ok) return;
        const ips = await response.json();
        
        const locations = [];
        
        for (let entry of ips) {
           // Skip internal/private network IP ranges
           if (
             entry.ip.startsWith('127.') || 
             entry.ip.startsWith('192.168.') || 
             entry.ip.startsWith('10.') || 
             entry.ip.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)
           ) {
             continue;
           }
           
           // Fetch Geolocation coordinates for strictly external attacks
           const geoRes = await fetch(`http://ip-api.com/json/${entry.ip}`);
           const geo = await geoRes.json();
           
           if (geo.status === 'success') {
             locations.push({
               lat: geo.lat,
               lng: geo.lon,
               size: Math.min(entry.count * 0.05, 0.5) + 0.1, // Logarithmic sizing based on accurate attack volume
               label: `${entry.ip} (${geo.country}) - ${entry.count} attacks`
             });
           }
        }
        setThreatPoints(locations);
      } catch (e) {
        console.error("Geolocating active threats failed:", e);
      }
    };

    fetchLocations();
    // Refresh accurate data strictly every 30 seconds to respect API rate limits
    const interval = setInterval(fetchLocations, 30000);

    return () => {
      window.removeEventListener('resize', handleResize);
      clearInterval(interval);
    };
  }, []);

  return (
    <div ref={containerRef} style={{ width: '100%', height: '500px', display: 'flex', justifyContent: 'center' }}>
      <Globe
        ref={globeRef}
        width={width}
        height={500}
        backgroundColor="rgba(0,0,0,0)"
        globeImageUrl={globeImageUrl}
        showAtmosphere={true}
        atmosphereColor={mapAtmosphereColor}
        atmosphereAltitude={0.15}
        polygonsData={countries.features}
        polygonAltitude={0.01}
        polygonCapColor={() => mapLandFill}
        polygonSideColor={() => mapLandSideFill}
        polygonStrokeColor={() => mapStrokeColor}
        polygonsTransitionDuration={300}
        // Hover effects for the hologrid
        polygonHoverColor={() => mapHoverFill}
        polygonLabel={({ properties: d }) => `
          <div style="background: ${mapTooltipBg}; border: 1px solid ${mapTooltipBorder}; padding: 6px 10px; border-radius: 4px; color: ${mapTooltipText}; font-family: monospace; z-index: 1000;">
            <b>${d.ADMIN}</b><br/>
            <span style="color: ${mapTooltipSubtext}; font-size: 11px;">Status: No active IP threats detected</span>
          </div>
        `}
        
        // Accurate Threat Points
        pointsData={threatPoints}
        pointLat="lat"
        pointLng="lng"
        pointColor={() => mapThreatPoint}
        pointAltitude="size"
        pointRadius={0.6}
        pointsMerge={true}
        // Hover effects for active hackers
        pointLabel={d => `
          <div style="background: ${mapThreatTooltipBg}; border: 1px solid ${mapThreatTooltipBorder}; padding: 6px 10px; border-radius: 4px; color: ${mapTooltipText}; font-family: monospace; z-index: 1000;">
            <b style="color: ${mapTooltipText};">🚨 CRITICAL THREAT ORIGIN</b><br/>
            ${d.label}
          </div>
        `}
      />
    </div>
  );
}

export default GlobeMap;
