import { useState, useEffect } from 'react';

export function useVotedTasks() {
  const [votedTasks, setVotedTasks] = useState<string[]>([]);

  useEffect(() => {
    // This only runs on the client, AFTER the initial render to prevent SSR hydration mismatches
    try {
      const storedA = window.localStorage.getItem('brone_voted_tasks');
      const storedB = window.localStorage.getItem('voted_posts');
      const listA = storedA ? JSON.parse(storedA) : [];
      const listB = storedB ? JSON.parse(storedB) : [];
      const combined = Array.from(new Set([...listA, ...listB]));
      setVotedTasks(combined);
    } catch (error) {
      console.error("Error reading voted_posts from localStorage", error);
    }
  }, []);

  const addVotedTask = (taskId: string) => {
    if (!taskId) return;
    setVotedTasks((prev) => {
      if (prev.includes(taskId)) return prev;
      const updated = [...prev, taskId];
      try {
        window.localStorage.setItem('brone_voted_tasks', JSON.stringify(updated));
        window.localStorage.setItem('voted_posts', JSON.stringify(updated));
      } catch (e) {
        console.error("Failed to write to localStorage", e);
      }
      return updated;
    });
  };

  return { votedTasks, addVotedTask };
}
