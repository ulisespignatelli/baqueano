import { NavLink, Outlet } from "react-router-dom";
import { api } from "@/shared/api";
import { useHealth } from "@/shared/api/queries";
import { sourceLabel } from "@/shared/lib/labels";
import { IconBug, IconEye, IconGithub, IconPlus, IconShield } from "./icons";

const REPO = "https://github.com/ulisespignatelli/baqueano";

export function Layout() {
  const health = useHealth();
  return (
    <div className="shell">
      <aside className="side">
        <NavLink to="/" className="brand" end>
          <img src={`${import.meta.env.BASE_URL}favicon.svg`} alt="" />
          <span>
            <b>Baqueano</b>
            <small>superficie externa de ataque</small>
          </span>
        </NavLink>
        <nav className="nav" aria-label="Principal">
          <NavLink to="/" end>
            <IconEye /> Vista general
          </NavLink>
          {api.mode === "api" && (
            <NavLink to="/orgs/new">
              <IconPlus /> Nueva organización
            </NavLink>
          )}
          <NavLink to="/intel">
            <IconBug /> Inteligencia
          </NavLink>
          <NavLink to="/about">
            <IconShield /> Cómo funciona
          </NavLink>
          <a href={REPO} target="_blank" rel="noreferrer">
            <IconGithub /> Código
          </a>
        </nav>
        <div className="side__foot">
          {health.data ? (
            <>
              <b>{sourceLabel[health.data.exposure_source] ?? health.data.exposure_source}</b>
              <br />
              versión {health.data.version}
            </>
          ) : health.isError ? (
            "Sin conexión con el servidor"
          ) : (
            "…"
          )}
        </div>
      </aside>
      <main className="main">
        {api.mode === "demo" && (
          <div className="demo-banner">
            <span>
              Demo con <b>organizaciones ficticias</b> (dominios .example, IP de documentación, CVE inventadas).
            </span>
            <a href={REPO}>Ver en GitHub →</a>
          </div>
        )}
        <Outlet />
      </main>
    </div>
  );
}
