import React, { useEffect, useState } from "react";
import axios from "axios";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

interface AttackData {
  name: string;
  value: number;
}

const Dashboard: React.FC = () => {
  const [data, setData] = useState<AttackData[]>([]);
  const [prediction, setPrediction] = useState<string | null>(null);

  useEffect(() => {
    axios.get("/attack_counts.json")
      .then((res) => {
        const chartData = Object.entries(res.data).map(([key, value]) => ({
          name: key,
          value: Number(value),
        }));
        setData(chartData);
      })
      .catch((err) => console.error(err));
  }, []);

  const handlePredict = async () => {
    try {
      const response = await axios.post("http://127.0.0.1:8000/predict", {
        // 🔸 Ejemplo de datos simulados (debes usar las mismas columnas que tu modelo)
        duration: 0,
        protocol_type: 1,
        service: 10,
        flag: 2,
        src_bytes: 181,
        dst_bytes: 5450,
        land: 0,
        wrong_fragment: 0,
        urgent: 0
        // ...
      });
      setPrediction(`Predicción: ${response.data.prediction}`);
    } catch (error) {
      console.error("Error al hacer predicción", error);
    }
  };

  return (
    <div style={{ width: "80%", height: 400, margin: "auto", marginTop: 50 }}>
      <h2>Distribución de ataques (NSL-KDD)</h2>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 20, right: 30, bottom: 20, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip />
          <Bar dataKey="value" fill="#8884d8" />
        </BarChart>
      </ResponsiveContainer>

      <button
        onClick={handlePredict}
        style={{ marginTop: 30, padding: "10px 20px", cursor: "pointer" }}
      >
        Probar predicción
      </button>

      {prediction && <p style={{ marginTop: 20 }}>{prediction}</p>}
    </div>
  );
};

export default Dashboard;
