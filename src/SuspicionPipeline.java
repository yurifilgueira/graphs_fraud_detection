import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

/**
 * Classe principal do pipeline de detecção de transações suspeitas.
 */
public class SuspicionPipeline {

    // --- PARÂMETROS DE DETECÇÃO ---
    private static final double TOLERANCE = 0.05;
    private static final long SMURF_WINDOW_MINUTES = 6000;
    private static final double SMURF_UNIT_LIMIT = 20000.0;
    private static final int SMURF_MIN_TX = 5;
    private static final int LAYERING_MAX_DEPTH = 4;
    private static final double LAYERING_DELTA = 5000.0;
    private static final long LAYERING_TIME_WINDOW_MINUTES = 2880;
    private static final int DENSE_MIN_DEGREE = 2;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            printDatasetMenu();
            String datasetChoice = scanner.nextLine();
            String selectedFile = null;

            switch (datasetChoice) {
                case "1":
                    selectedFile = "fraud_dataset.csv";
                    break;
                case "2":
                    selectedFile = "not_fraud_dataset.csv";
                    break;
                case "3":
                    selectedFile = "full_dataset.csv";
                    break;
                case "4":
                    selectedFile = "small_not_fraud_dataset.csv";
                    break;
                case "5":
                    System.out.println("Saindo do programa. Até mais!");
                    return;
                default:
                    System.out.println("Opção inválida. Por favor, tente novamente.");
                    continue;
            }

            printAlgorithmMenu();
            String algorithmChoice = scanner.nextLine();
            if (algorithmChoice.equals("6")) {
                continue;
            }

            runAnalysis(selectedFile, algorithmChoice);
            System.out.println("\nPressione Enter para voltar ao menu principal...");
            scanner.nextLine();
        }
    }

    private static void printDatasetMenu() {
        System.out.println("\n--- Pipeline de Detecção de Fraudes ---");
        System.out.println("Etapa 1: Escolha o conjunto de dados para analisar:");
        System.out.println("1. Dataset com Fraudes (fraud_dataset.csv)");
        System.out.println("2. Dataset sem Fraudes (not_fraud_dataset.csv)");
        System.out.println("3. Dataset Completo (full_dataset.csv)");
        System.out.println("4. Dataset Pequeno sem Fraudes (small_not_fraud_dataset.csv)");
        System.out.println("5. Sair");
        System.out.print("Escolha uma opção: ");
    }

    private static void printAlgorithmMenu() {
        System.out.println("\nEtapa 2: Escolha qual algoritmo de detecção executar:");
        System.out.println("1. Apenas Desequilíbrio de Fluxo");
        System.out.println("2. Apenas Smurfing");
        System.out.println("3. Apenas Layering");
        System.out.println("4. Apenas Comunidades Densas");
        System.out.println("5. Executar TODOS os algoritmos (Pipeline Completo)");
        System.out.println("6. Voltar ao menu anterior");
        System.out.print("Escolha uma opção: ");
    }

    private static void runAnalysis(String fileName, String algorithmChoice) {
        if (!Files.exists(Paths.get(fileName))) {
            System.err.println("\nERRO: O arquivo '" + fileName + "' não foi encontrado!");
            return;
        }

        System.out.println("\n=============================================");
        System.out.println("Iniciando análise do arquivo: " + fileName);

        List<Transaction> transactions = loadTransactions(fileName);
        System.out.println("Total de transações carregadas: " + transactions.size());

        if (transactions.isEmpty()) {
            System.err.println("Nenhuma transação válida encontrada no arquivo.");
            return;
        }

        Map<String, Long> executionTimes = new LinkedHashMap<>();
        List<Suspicion> allAlerts = new ArrayList<>();
        long algorithmsTotalTime = 0;

        if (algorithmChoice.equals("1") || algorithmChoice.equals("5")) {
            System.out.println("Executando FlowChecker...");
            long startTime = System.nanoTime();
            FlowChecker flowChecker = new FlowChecker();
            allAlerts.addAll(flowChecker.check(transactions));
            long duration = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            executionTimes.put("FlowChecker", duration);
            algorithmsTotalTime += duration;
        }

        if (algorithmChoice.equals("2") || algorithmChoice.equals("5")) {
            System.out.println("Executando SmurfingDetector...");
            long startTime = System.nanoTime();
            SmurfingDetector smurfDetector = new SmurfingDetector(SMURF_WINDOW_MINUTES, SMURF_UNIT_LIMIT, SMURF_MIN_TX);
            allAlerts.addAll(smurfDetector.detect(transactions));
            long duration = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            executionTimes.put("SmurfingDetector", duration);
            algorithmsTotalTime += duration;
        }

        if (algorithmChoice.equals("3") || algorithmChoice.equals("5")) {
            System.out.println("Executando LayeringDetector...");
            long startTime = System.nanoTime();
            LayeringDetector layeringDetector = new LayeringDetector(LAYERING_MAX_DEPTH, LAYERING_DELTA, LAYERING_TIME_WINDOW_MINUTES);
            allAlerts.addAll(layeringDetector.detect(transactions));
            long duration = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            executionTimes.put("LayeringDetector", duration);
            algorithmsTotalTime += duration;
        }

        if (algorithmChoice.equals("4") || algorithmChoice.equals("5")) {
            System.out.println("Executando CommunityDetector...");
            long startTime = System.nanoTime();
            CommunityDetector communityDetector = new CommunityDetector(DENSE_MIN_DEGREE);
            allAlerts.addAll(communityDetector.detect(transactions));
            long duration = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            executionTimes.put("CommunityDetector", duration);
            algorithmsTotalTime += duration;
        }

        System.out.println("Unificando e rankeando os alertas...");
        RiskRanker ranker = new RiskRanker();
        List<Suspicion> ranked = ranker.rank(allAlerts);

        String analysisType = algorithmChoice.equals("5") ? "all_algorithms" : "algo_" + algorithmChoice;
        String resultsCsvFile = "suspicion_results_for_" + fileName.replace(".csv", "") + "_" + analysisType + ".csv";
        String timesTxtFile = "execution_times_for_" + fileName.replace(".csv", "") + "_" + analysisType + ".txt";

        saveResultsToCsv(ranked, resultsCsvFile);
        saveExecutionTimes(executionTimes, algorithmsTotalTime, timesTxtFile);

        System.out.println("\n--- RESULTADO DAS ANÁLISES DE SUSPEITA ---");
        if (ranked.isEmpty()) {
            System.out.println("Nenhuma fraude detectada com a configuração selecionada.");
        } else {
            for (Suspicion s : ranked) {
                System.out.println(s);
            }
        }

        System.out.println("\n--- TEMPO DE EXECUÇÃO ---");
        if (executionTimes.isEmpty()){
            System.out.println("Nenhum algoritmo foi executado para esta opção.");
        } else {
            for (Map.Entry<String, Long> entry : executionTimes.entrySet()) {
                System.out.println(entry.getKey() + ": " + entry.getValue() + " ms");
            }
        }
        System.out.println("--------------------------------------");
        System.out.println("Tempo Total dos Algoritmos: " + algorithmsTotalTime + " ms");

        System.out.println("\nAnálise concluída.");
        System.out.println("Resultados salvos em '" + resultsCsvFile + "'");
        System.out.println("Tempos de execução salvos em '" + timesTxtFile + "'");
        System.out.println("=============================================");
    }

    private static List<Transaction> loadTransactions(String fileName) {
        System.out.println(">>> Abrindo " + fileName);
        List<Transaction> list = new ArrayList<>();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm");

        try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
            String line;
            br.readLine();

            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty() || line.contains("BEGIN LAUNDERING ATTEMPT") || line.contains("END LAUNDERING ATTEMPT")) {
                    continue;
                }
                String[] parts = line.split(",");
                if (parts.length < 11) continue;

                try {
                    LocalDateTime timestamp = LocalDateTime.parse(parts[0].trim(), formatter);
                    String origin = parts[2].trim();
                    String destination = parts[4].trim();
                    double amount = Double.parseDouble(parts[5].trim());
                    Transaction tx = new Transaction(origin, destination, amount, timestamp);
                    list.add(tx);
                } catch (Exception e) {
                    System.err.println("    Erro ao processar a linha: " + line + " -> " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Erro ao ler o arquivo: " + e.getMessage());
            e.printStackTrace();
        }
        return list;
    }

    private static void saveResultsToCsv(List<Suspicion> results, String fileName) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(fileName))) {
            pw.println("Account,Reason,Score,EvidenceCount");
            if (results.isEmpty()) {
                pw.println("Nenhuma fraude detectada,,,");
            } else {
                for (Suspicion s : results) {
                    String reason = "\"" + s.reason.replace("\"", "\"\"") + "\"";
                    pw.println(s.account + "," + reason + "," + s.score + "," + s.evidence.size());
                }
            }
        } catch (IOException e) {
            System.err.println("Erro ao salvar resultados no CSV: " + e.getMessage());
        }
    }

    private static void saveExecutionTimes(Map<String, Long> times, long totalTime, String fileName) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(fileName))) {
            pw.println("--- TEMPO DE EXECUÇÃO DOS ALGORITMOS ---");
            if (times.isEmpty()){
                pw.println("Nenhum algoritmo foi executado para esta opção.");
            } else {
                for (Map.Entry<String, Long> entry : times.entrySet()) {
                    pw.println(entry.getKey() + ": " + entry.getValue() + " ms");
                }
            }
            pw.println("--------------------------------------");
            pw.println("Tempo de Execução Total dos Algoritmos: " + totalTime + " ms");
        } catch (IOException e) {
            System.err.println("Erro ao salvar tempos de execução: " + e.getMessage());
        }
    }
}

/**
 * Representa uma transação financeira.
 */
class Transaction {
    public final String origin;
    public final String destination;
    public final double amount;
    public final LocalDateTime timestamp;

    public Transaction(String o, String d, double a, LocalDateTime t) {
        this.origin = o;
        this.destination = d;
        this.amount = a;
        this.timestamp = t;
    }
}

/**
 * Armazena informações de suspeita identificada.
 */
class Suspicion {
    public final String account;
    public final String reason;
    public final int score;
    public final List<Transaction> evidence;

    public Suspicion(String account, String reason, int score, List<Transaction> evidence) {
        this.account = account;
        this.reason = reason;
        this.score = score;
        this.evidence = evidence;
    }

    @Override
    public String toString() {
        return String.format("Conta: %s | Motivo: %s | Score: %d | Evidências: %d transações", 
            account, reason, score, evidence.size());
    }
}

class FlowChecker {
    private static final double LIMITE_SUSPEITO = 100000.0;
    public List<Suspicion> check(List<Transaction> transactions) {
        Map<String, Double> balancoContas = new HashMap<>();
        for (Transaction tx : transactions) {
            balancoContas.merge(tx.destination, tx.amount, Double::sum);
            balancoContas.merge(tx.origin, -tx.amount, Double::sum);
        }
        List<Suspicion> results = new ArrayList<>();
        for (Map.Entry<String, Double> entry : balancoContas.entrySet()) {
            String idDaConta = entry.getKey();
            Double valorDoBalanco = entry.getValue();
            if (valorDoBalanco < -LIMITE_SUSPEITO) {
                Suspicion alerta = new Suspicion(idDaConta, "Desequilíbrio de fluxo", 1, filterByAccount(transactions, idDaConta));
                results.add(alerta);
            }
        }
        return results;
    }

    private List<Transaction> filterByAccount(List<Transaction> txs, String acc) {
        List<Transaction> list = new ArrayList<>();
        for (Transaction tx : txs) {
            if (tx.origin.equals(acc) || tx.destination.equals(acc)) {
                list.add(tx);
            }
        }
        return list;
    }
}

class SmurfingDetector {
    private final long windowMinutes; private final double unitLimit; private final int minTx;
    public SmurfingDetector(long w, double u, int m) { windowMinutes = w; unitLimit = u; minTx = m; }
    public List<Suspicion> detect(List<Transaction> transactions) {
        Map<String, List<Transaction>> byOrigin = new HashMap<>();
        for (Transaction tx : transactions) byOrigin.computeIfAbsent(tx.origin, k -> new ArrayList<>()).add(tx);
        List<Suspicion> results = new ArrayList<>();
        for (Map.Entry<String, List<Transaction>> e : byOrigin.entrySet()) {
            List<Transaction> ev = e.getValue();
            ev.sort(Comparator.comparing(t -> t.timestamp));
            for (int i = 0; i < ev.size(); i++) {
                int cnt = 0; List<Transaction> grp = new ArrayList<>();
                for (int j = i; j < ev.size(); j++) {
                    long diff = ChronoUnit.MINUTES.between(ev.get(i).timestamp, ev.get(j).timestamp);
                    if (diff <= windowMinutes && ev.get(j).amount <= unitLimit) {
                        cnt++; grp.add(ev.get(j));
                    } else break;
                }
                if (cnt >= minTx) { results.add(new Suspicion(e.getKey(), "Smurfing detectado", 2, grp)); break; }
            }
        }
        return results;
    }
}

class LayeringDetector {
    private final int maxDepth; private final double delta; private final long timeWindow;
    public LayeringDetector(int d, double v, long t) { maxDepth = d; delta = v; timeWindow = t; }
    public List<Suspicion> detect(List<Transaction> transactions) {
        Map<String, List<Transaction>> map = new HashMap<>();
        for (Transaction tx : transactions) map.computeIfAbsent(tx.origin, k -> new ArrayList<>()).add(tx);
        List<Suspicion> res = new ArrayList<>();
        for (Transaction tx : transactions) dfs(tx.origin, tx.destination, tx.amount, tx.timestamp,
            new LinkedHashSet<>(Arrays.asList(tx.origin, tx.destination)), map, new ArrayList<>(Arrays.asList(tx)), res);
        return res;
    }
    private void dfs(String src, String cur, double prevAmt, LocalDateTime prevTime,
                     Set<String> vis, Map<String, List<Transaction>> map,
                     List<Transaction> path, List<Suspicion> res) {
        if (path.size() >= maxDepth) { res.add(new Suspicion(src, "Layering detectado", 3, new ArrayList<>(path))); return; }
        for (Transaction nxt : map.getOrDefault(cur, Collections.emptyList())) {
            if (!vis.contains(nxt.destination)) {
                long diff = ChronoUnit.MINUTES.between(prevTime, nxt.timestamp);
                if (diff <= timeWindow && Math.abs(nxt.amount - prevAmt) <= delta) {
                    vis.add(nxt.destination); path.add(nxt);
                    dfs(src, nxt.destination, nxt.amount, nxt.timestamp, vis, map, path, res);
                    path.remove(path.size() - 1); vis.remove(nxt.destination);
                }
            }
        }
    }
}

/*
 * Detecta comunidades densas via k-core (grau mínimo DENSE_MIN_DEGREE).
*/
class CommunityDetector {
    private final int minDegree;

    public CommunityDetector(int d) {
        minDegree = d;
    }

    public List<Suspicion> detect(List<Transaction> txs) {
        Map<String, Set<String>> adj = new HashMap<>();
        for (Transaction tx : txs) {
            adj.computeIfAbsent(tx.origin, k -> new HashSet<>()).add(tx.destination);
            adj.computeIfAbsent(tx.destination, k -> new HashSet<>()).add(tx.origin);
        }

        Queue<String> queue = new LinkedList<>();
        Map<String, Integer> degrees = new HashMap<>();
        for(Map.Entry<String, Set<String>> e : adj.entrySet()){
            degrees.put(e.getKey(), e.getValue().size());
        }

        for (Map.Entry<String, Integer> e : degrees.entrySet()) {
            if (e.getValue() < minDegree) {
                queue.add(e.getKey());
            }
        }

        Set<String> removedNodes = new HashSet<>();

        while (!queue.isEmpty()) {
            String v = queue.poll();
            if(removedNodes.contains(v)) continue;
            removedNodes.add(v);

            for (String neighbor : adj.getOrDefault(v, Collections.emptySet())) {
                if (!removedNodes.contains(neighbor)) {
                    degrees.put(neighbor, degrees.get(neighbor) - 1);
                    if (degrees.get(neighbor) < minDegree) {
                        queue.add(neighbor);
                    }
                }
            }
        }

        adj.keySet().removeAll(removedNodes);

        List<Suspicion> res = new ArrayList<>();
        if (!adj.isEmpty()) {
            Set<String> community = adj.keySet();
            List<Transaction> evid = new ArrayList<>();
            for (Transaction tx : txs) {
                if (community.contains(tx.origin) && community.contains(tx.destination)) {
                    evid.add(tx);
                }
            }
            for (String acc : community) {
                res.add(new Suspicion(acc, "Comunidade densa", 2, evid));
            }
        }
        return res;
    }
}

class RiskRanker {
    public List<Suspicion> rank(List<Suspicion> alerts) {
        Map<String, Suspicion> merged = new HashMap<>();
        for (Suspicion s : alerts) {
            merged.merge(s.account, s, (oldS, newS) -> new Suspicion(
                oldS.account,
                oldS.reason + "; " + newS.reason,
                oldS.score + newS.score,
                concat(oldS.evidence, newS.evidence)
            ));
        }
        List<Suspicion> list = new ArrayList<>(merged.values());
        list.sort(Comparator.comparingInt((Suspicion s) -> s.score).reversed());
        return list;
    }
    private List<Transaction> concat(List<Transaction> a, List<Transaction> b) {
        List<Transaction> c = new ArrayList<>(a);
        c.addAll(b);
        return c;
    }
}
