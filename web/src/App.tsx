/**
 * Root App component with React Router.
 *
 * V3App (Threat Hunter Workbench) is the shipped product, rendered at the root.
 */
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import V3App from './variants/v3/App';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/*" element={<V3App basePath="/" />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
