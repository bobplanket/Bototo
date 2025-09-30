import { useEffect, useState } from 'react';
import axios from 'axios';

interface Position {
  symbol: string;
  qty: number;
  avg_price: number;
  realized_pnl: number;
  unrealized_pnl: number;
}

function App() {
  const [positions, setPositions] = useState<Position[]>([]);
  const [status, setStatus] = useState('unknown');

  useEffect(() => {
    axios.get('/api/positions').then((response) => setPositions(response.data));
    axios.get('/health').then(() => setStatus('ok')).catch(() => setStatus('error'));
  }, []);

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <header className="p-4 border-b border-slate-800">
        <h1 className="text-2xl font-semibold">AutoLLM Trader Admin</h1>
        <p className="text-sm text-slate-400">Status: {status}</p>
      </header>
      <section className="p-4">
        <h2 className="text-xl mb-2">Open Positions</h2>
        <table className="w-full text-left border-collapse">
          <thead>
            <tr>
              <th>Symbol</th>
              <th>Qty</th>
              <th>Avg Price</th>
              <th>Realized PnL</th>
              <th>Unrealized PnL</th>
            </tr>
          </thead>
          <tbody>
            {positions.map((pos) => (
              <tr key={pos.symbol}>
                <td>{pos.symbol}</td>
                <td>{pos.qty}</td>
                <td>{pos.avg_price.toFixed(2)}</td>
                <td>{pos.realized_pnl.toFixed(2)}</td>
                <td>{pos.unrealized_pnl.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}

export default App;
