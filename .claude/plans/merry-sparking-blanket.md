# Implementation Plan: Single-Process Frontend/Backend Deployment

## Context
The user wants to simplify the project deployment to a one-click process that runs everything in a single terminal, serves the dashboard through the backend, and provides results in that dashboard. Currently, the project runs a Flask API and a Vite dev server separately, which the user finds complex to manage.

## Proposed Approach
1. **Frontend Build**: Add a build step to the launcher that runs `npm run build` in `artifact-pulse-ui/` to generate production static assets.
2. **Backend Serving**: Modify the Flask backend (`web/app.py`) to serve these static assets (index.html, JS, CSS) from the build directory. This will allow the Flask app to act as both the API server and the static file server.
3. **Launcher Simplification**: Update `START.bat` to:
    - Automatically run the frontend build step if `node_modules` or `dist` (if applicable) are present/missing.
    - Start only the Flask backend.
    - Remove the code that launches the Vite dev server and polls it for readiness.
    - Open the browser to the single URL served by Flask.

## Critical Files to Modify
- `artifact-pulse-ui/package.json` (ensure build output is compatible/standardized)
- `web/app.py` (add static file routing)
- `START.bat` (update launch sequence)

## Implementation Steps
1. **Flask Static Serving**: In `web/app.py`, configure Flask to serve static files from the frontend's build folder (e.g., `../artifact-pulse-ui/dist`) and ensure that SPA routing (React Router) is handled by serving `index.html` for non-API routes.
2. **Build Automation**: Update `START.bat` to detect changes and rebuild frontend if needed, or always rebuild to be safe.
3. **Refactor Launch**:
    - Remove `start "Artifact-Pulse UI (close to stop)"...` block from `START.bat`.
    - Keep backend startup.
    - Change browser open URL to the backend port (e.g., `http://127.0.0.1:5000`).

## Verification Plan
- Run `START.bat`.
- Verify the backend starts successfully.
- Ensure the frontend loads correctly when accessing `http://127.0.0.1:5000`.
- Test that API calls to `/api/...` still function correctly.
