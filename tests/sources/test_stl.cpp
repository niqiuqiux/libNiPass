/**
 * NiPass STL 复杂仿真测试
 *
 * 覆盖场景：
 *   - 容器：vector, map, unordered_map, set, deque, list, priority_queue
 *   - 算法：sort, transform, accumulate, find_if, partition, remove_if
 *   - 字符串操作：string, string_view, stringstream
 *   - 智能指针：unique_ptr, shared_ptr
 *   - 函数式：std::function, lambda, std::bind
 *   - 迭代器与范围操作
 *   - std::optional, std::variant, std::any
 *   - 异常处理路径
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <deque>
#include <list>
#include <queue>
#include <stack>
#include <algorithm>
#include <numeric>
#include <functional>
#include <memory>
#include <sstream>
#include <optional>
#include <variant>
#include <any>
#include <array>
#include <tuple>
#include <utility>
#include <type_traits>
#include <cassert>

/* ========================================================================
 * 敏感字符串 — 字符串加密目标
 * ======================================================================== */

static const char *DB_CONNECTION_STR = "postgresql://admin:s3cret@db.nipass.internal:5432/prod";
static const char *REDIS_AUTH_TOKEN  = "redis://default:Rds$2024!xKm@cache.nipass.internal:6379";
static const char *JWT_SIGNING_KEY   = "HS256::nipass-jwt-secret-key-do-not-leak-2024";
static const char *ENCRYPTION_IV     = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

/* ========================================================================
 * 测试框架
 * ======================================================================== */

static int g_tests_run    = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (cond) { g_tests_passed++; } \
    else { g_tests_failed++; printf("  FAIL: %s (line %d)\n", msg, __LINE__); } \
} while(0)

/* ========================================================================
 * 1. 容器综合测试 — 大量分支 + 迭代器操作
 * ======================================================================== */

struct Order {
    uint32_t    id;
    std::string customer;
    double      amount;
    int         priority;   // 1=high, 2=medium, 3=low
    std::string status;     // "pending", "processing", "shipped", "delivered"

    bool operator<(const Order &o) const { return amount > o.amount; } // 按金额降序
};

class OrderBook {
    std::vector<Order> orders_;
    std::map<uint32_t, size_t> id_index_;           // id -> orders_ 下标
    std::unordered_map<std::string, std::vector<uint32_t>> customer_index_;
    std::set<uint32_t> high_priority_ids_;
    uint32_t next_id_ = 1000;

public:
    uint32_t add_order(const std::string &customer, double amount, int priority) {
        uint32_t id = next_id_++;
        orders_.push_back({id, customer, amount, priority, "pending"});
        id_index_[id] = orders_.size() - 1;
        customer_index_[customer].push_back(id);
        if (priority == 1) high_priority_ids_.insert(id);
        return id;
    }

    bool update_status(uint32_t id, const std::string &new_status) {
        auto it = id_index_.find(id);
        if (it == id_index_.end()) return false;
        orders_[it->second].status = new_status;
        return true;
    }

    std::optional<Order> find_order(uint32_t id) const {
        auto it = id_index_.find(id);
        if (it == id_index_.end()) return std::nullopt;
        return orders_[it->second];
    }

    std::vector<Order> get_customer_orders(const std::string &customer) const {
        std::vector<Order> result;
        auto it = customer_index_.find(customer);
        if (it == customer_index_.end()) return result;
        for (uint32_t oid : it->second) {
            auto idx = id_index_.find(oid);
            if (idx != id_index_.end())
                result.push_back(orders_[idx->second]);
        }
        return result;
    }

    std::vector<Order> get_sorted_by_amount() const {
        auto sorted = orders_;
        std::sort(sorted.begin(), sorted.end());
        return sorted;
    }

    double total_revenue() const {
        return std::accumulate(orders_.begin(), orders_.end(), 0.0,
            [](double sum, const Order &o) { return sum + o.amount; });
    }

    size_t count_by_status(const std::string &status) const {
        return std::count_if(orders_.begin(), orders_.end(),
            [&](const Order &o) { return o.status == status; });
    }

    std::vector<Order> filter_high_value(double threshold) const {
        std::vector<Order> result;
        std::copy_if(orders_.begin(), orders_.end(), std::back_inserter(result),
            [threshold](const Order &o) { return o.amount >= threshold; });
        return result;
    }

    size_t high_priority_count() const { return high_priority_ids_.size(); }
    size_t total_count() const { return orders_.size(); }
};

/* ========================================================================
 * 2. 字符串处理引擎 — string/string_view/stringstream
 * ======================================================================== */

class TokenParser {
public:
    struct Token {
        std::string type;   // "keyword", "identifier", "number", "operator", "string"
        std::string value;
        int         line;
        int         col;
    };

    static std::vector<Token> tokenize(std::string_view input) {
        std::vector<Token> tokens;
        int line = 1, col = 1;
        size_t i = 0;

        while (i < input.size()) {
            // 跳过空白
            if (input[i] == ' ' || input[i] == '\t') { col++; i++; continue; }
            if (input[i] == '\n') { line++; col = 1; i++; continue; }

            // 数字
            if (input[i] >= '0' && input[i] <= '9') {
                size_t start = i;
                while (i < input.size() && ((input[i] >= '0' && input[i] <= '9') || input[i] == '.'))
                    i++;
                tokens.push_back({"number", std::string(input.substr(start, i - start)), line, col});
                col += (int)(i - start);
                continue;
            }

            // 标识符/关键字
            if ((input[i] >= 'a' && input[i] <= 'z') ||
                (input[i] >= 'A' && input[i] <= 'Z') || input[i] == '_') {
                size_t start = i;
                while (i < input.size() && ((input[i] >= 'a' && input[i] <= 'z') ||
                       (input[i] >= 'A' && input[i] <= 'Z') ||
                       (input[i] >= '0' && input[i] <= '9') || input[i] == '_'))
                    i++;
                std::string word(input.substr(start, i - start));
                static const std::set<std::string> keywords = {
                    "if", "else", "for", "while", "return", "class", "struct",
                    "int", "void", "const", "static", "virtual", "override"
                };
                std::string type = keywords.count(word) ? "keyword" : "identifier";
                tokens.push_back({type, std::move(word), line, col});
                col += (int)(i - start);
                continue;
            }

            // 字符串字面量
            if (input[i] == '"') {
                size_t start = ++i;
                while (i < input.size() && input[i] != '"') {
                    if (input[i] == '\\' && i + 1 < input.size()) i++;
                    i++;
                }
                tokens.push_back({"string", std::string(input.substr(start, i - start)), line, col});
                if (i < input.size()) i++; // skip closing "
                col += (int)(i - start + 2);
                continue;
            }

            // 运算符
            static const std::set<char> ops = {'+', '-', '*', '/', '=', '<', '>', '!', '&', '|', '^', '%'};
            if (ops.count(input[i])) {
                std::string op(1, input[i]);
                if (i + 1 < input.size()) {
                    std::string two = op + std::string(1, input[i + 1]);
                    static const std::set<std::string> double_ops = {
                        "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "<<", ">>"
                    };
                    if (double_ops.count(two)) { op = two; i++; }
                }
                tokens.push_back({"operator", op, line, col});
                col += (int)op.size();
                i++;
                continue;
            }

            // 其他单字符
            tokens.push_back({"operator", std::string(1, input[i]), line, col});
            col++; i++;
        }
        return tokens;
    }

    static std::string serialize(const std::vector<Token> &tokens) {
        std::ostringstream oss;
        for (size_t i = 0; i < tokens.size(); i++) {
            if (i > 0) oss << " ";
            oss << "[" << tokens[i].type << ":" << tokens[i].value << "]";
        }
        return oss.str();
    }
};

/* ========================================================================
 * 3. 事件系统 — std::function + lambda + 智能指针
 * ======================================================================== */

class EventBus {
public:
    using Handler = std::function<void(const std::string &, const std::any &)>;

    struct Subscription {
        uint32_t id;
        std::string event_name;
        Handler handler;
    };

    uint32_t subscribe(const std::string &event, Handler handler) {
        uint32_t id = next_sub_id_++;
        subs_.push_back({id, event, std::move(handler)});
        return id;
    }

    bool unsubscribe(uint32_t id) {
        auto it = std::find_if(subs_.begin(), subs_.end(),
            [id](const Subscription &s) { return s.id == id; });
        if (it == subs_.end()) return false;
        subs_.erase(it);
        return true;
    }

    int emit(const std::string &event, const std::any &data) {
        int count = 0;
        for (auto &sub : subs_) {
            if (sub.event_name == event) {
                sub.handler(event, data);
                count++;
            }
        }
        log_.push_back({event, count});
        return count;
    }

    size_t subscriber_count(const std::string &event) const {
        return std::count_if(subs_.begin(), subs_.end(),
            [&](const Subscription &s) { return s.event_name == event; });
    }

    const std::vector<std::pair<std::string, int>> &log() const { return log_; }

private:
    std::vector<Subscription> subs_;
    std::vector<std::pair<std::string, int>> log_;
    uint32_t next_sub_id_ = 1;
};

/* ========================================================================
 * 4. LRU 缓存 — list + unordered_map 组合
 * ======================================================================== */

template<typename K, typename V>
class LRUCache {
    size_t capacity_;
    std::list<std::pair<K, V>> items_;
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator> index_;
    size_t hits_ = 0, misses_ = 0;

public:
    explicit LRUCache(size_t cap) : capacity_(cap) {}

    std::optional<V> get(const K &key) {
        auto it = index_.find(key);
        if (it == index_.end()) { misses_++; return std::nullopt; }
        hits_++;
        items_.splice(items_.begin(), items_, it->second);
        return it->second->second;
    }

    void put(const K &key, const V &value) {
        auto it = index_.find(key);
        if (it != index_.end()) {
            it->second->second = value;
            items_.splice(items_.begin(), items_, it->second);
            return;
        }
        if (items_.size() >= capacity_) {
            auto &back = items_.back();
            index_.erase(back.first);
            items_.pop_back();
        }
        items_.emplace_front(key, value);
        index_[key] = items_.begin();
    }

    size_t size() const { return items_.size(); }
    size_t hits() const { return hits_; }
    size_t misses() const { return misses_; }
    double hit_rate() const {
        size_t total = hits_ + misses_;
        return total > 0 ? (double)hits_ / total : 0.0;
    }
};

/* ========================================================================
 * 5. 图结构 — deque BFS + set 去重 + priority_queue Dijkstra
 * ======================================================================== */

class Graph {
    std::map<std::string, std::vector<std::pair<std::string, int>>> adj_;

public:
    void add_edge(const std::string &from, const std::string &to, int weight = 1) {
        adj_[from].push_back({to, weight});
        adj_[to]; // 确保节点存在
    }

    std::vector<std::string> bfs(const std::string &start) const {
        std::vector<std::string> visited_order;
        std::set<std::string> visited;
        std::deque<std::string> queue;

        queue.push_back(start);
        visited.insert(start);

        while (!queue.empty()) {
            auto node = queue.front();
            queue.pop_front();
            visited_order.push_back(node);

            auto it = adj_.find(node);
            if (it == adj_.end()) continue;
            for (auto &[neighbor, _w] : it->second) {
                if (visited.insert(neighbor).second) {
                    queue.push_back(neighbor);
                }
            }
        }
        return visited_order;
    }

    std::map<std::string, int> dijkstra(const std::string &start) const {
        std::map<std::string, int> dist;
        for (auto &[node, _] : adj_) dist[node] = INT32_MAX;
        dist[start] = 0;

        using PQItem = std::pair<int, std::string>; // (dist, node)
        std::priority_queue<PQItem, std::vector<PQItem>, std::greater<>> pq;
        pq.push({0, start});

        while (!pq.empty()) {
            auto [d, u] = pq.top(); pq.pop();
            if (d > dist[u]) continue;

            auto it = adj_.find(u);
            if (it == adj_.end()) continue;
            for (auto &[v, w] : it->second) {
                int nd = d + w;
                if (nd < dist[v]) {
                    dist[v] = nd;
                    pq.push({nd, v});
                }
            }
        }
        return dist;
    }

    size_t node_count() const { return adj_.size(); }
};

/* ========================================================================
 * 6. variant 状态机 — std::variant + std::visit
 * ======================================================================== */

namespace json {
    struct Null {};
    struct Bool { bool value; };
    struct Number { double value; };
    struct String { std::string value; };
    struct Array;
    struct Object;

    using Value = std::variant<Null, Bool, Number, String,
                               std::shared_ptr<Array>, std::shared_ptr<Object>>;

    struct Array { std::vector<Value> elements; };
    struct Object { std::map<std::string, Value> fields; };

    std::string stringify(const Value &v) {
        return std::visit([](auto &&arg) -> std::string {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, Null>) return "null";
            else if constexpr (std::is_same_v<T, Bool>) return arg.value ? "true" : "false";
            else if constexpr (std::is_same_v<T, Number>) {
                char buf[64];
                snprintf(buf, sizeof(buf), "%.6g", arg.value);
                return buf;
            }
            else if constexpr (std::is_same_v<T, String>) return "\"" + arg.value + "\"";
            else if constexpr (std::is_same_v<T, std::shared_ptr<Array>>) {
                std::string s = "[";
                for (size_t i = 0; i < arg->elements.size(); i++) {
                    if (i > 0) s += ",";
                    s += stringify(arg->elements[i]);
                }
                return s + "]";
            }
            else if constexpr (std::is_same_v<T, std::shared_ptr<Object>>) {
                std::string s = "{";
                bool first = true;
                for (auto &[k, val] : arg->fields) {
                    if (!first) s += ",";
                    s += "\"" + k + "\":" + stringify(val);
                    first = false;
                }
                return s + "}";
            }
            else return "?";
        }, v);
    }

    bool is_truthy(const Value &v) {
        return std::visit([](auto &&arg) -> bool {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, Null>) return false;
            else if constexpr (std::is_same_v<T, Bool>) return arg.value;
            else if constexpr (std::is_same_v<T, Number>) return arg.value != 0.0;
            else if constexpr (std::is_same_v<T, String>) return !arg.value.empty();
            else return true;
        }, v);
    }
}

/* ========================================================================
 * 7. 测试用例
 * ======================================================================== */

static void test_order_book() {
    printf("[TEST] OrderBook (vector/map/unordered_map/set)\n");

    OrderBook book;
    auto id1 = book.add_order("alice", 250.0, 1);
    auto id2 = book.add_order("bob",   100.0, 3);
    auto id3 = book.add_order("alice", 500.0, 2);
    auto id4 = book.add_order("charlie", 75.0, 1);
    auto id5 = book.add_order("bob",   300.0, 2);

    TEST_ASSERT(book.total_count() == 5, "5 orders added");
    TEST_ASSERT(book.high_priority_count() == 2, "2 high priority");

    auto found = book.find_order(id1);
    TEST_ASSERT(found.has_value(), "find order by id");
    TEST_ASSERT(found->customer == "alice", "correct customer");
    TEST_ASSERT(found->status == "pending", "initial status pending");

    TEST_ASSERT(!book.find_order(9999).has_value(), "missing order returns nullopt");

    auto alice_orders = book.get_customer_orders("alice");
    TEST_ASSERT(alice_orders.size() == 2, "alice has 2 orders");

    book.update_status(id1, "shipped");
    book.update_status(id2, "shipped");
    book.update_status(id3, "processing");
    TEST_ASSERT(book.count_by_status("shipped") == 2, "2 shipped");
    TEST_ASSERT(book.count_by_status("pending") == 2, "2 still pending");

    double rev = book.total_revenue();
    TEST_ASSERT(rev > 1224.9 && rev < 1225.1, "total revenue ~1225");

    auto sorted = book.get_sorted_by_amount();
    TEST_ASSERT(sorted[0].amount >= sorted[1].amount, "sorted descending");

    auto high_val = book.filter_high_value(200.0);
    TEST_ASSERT(high_val.size() == 3, "3 orders >= 200");
}

static void test_tokenizer() {
    printf("[TEST] TokenParser (string/string_view/stringstream)\n");

    auto tokens = TokenParser::tokenize("int x = 42 + y;");
    TEST_ASSERT(tokens.size() == 7, "7 tokens parsed");
    TEST_ASSERT(tokens[0].type == "keyword" && tokens[0].value == "int", "keyword int");
    TEST_ASSERT(tokens[1].type == "identifier" && tokens[1].value == "x", "identifier x");
    TEST_ASSERT(tokens[2].type == "operator" && tokens[2].value == "=", "operator =");
    TEST_ASSERT(tokens[3].type == "number" && tokens[3].value == "42", "number 42");

    auto tokens2 = TokenParser::tokenize("if (a >= b && c != 0) return a;");
    bool has_ge = std::any_of(tokens2.begin(), tokens2.end(),
        [](const TokenParser::Token &t) { return t.value == ">="; });
    bool has_ne = std::any_of(tokens2.begin(), tokens2.end(),
        [](const TokenParser::Token &t) { return t.value == "!="; });
    bool has_and = std::any_of(tokens2.begin(), tokens2.end(),
        [](const TokenParser::Token &t) { return t.value == "&&"; });
    TEST_ASSERT(has_ge, "parsed >=");
    TEST_ASSERT(has_ne, "parsed !=");
    TEST_ASSERT(has_and, "parsed &&");

    auto tokens3 = TokenParser::tokenize(R"(const char *s = "hello world";)");
    bool has_str = std::any_of(tokens3.begin(), tokens3.end(),
        [](const TokenParser::Token &t) { return t.type == "string"; });
    TEST_ASSERT(has_str, "parsed string literal");

    auto serialized = TokenParser::serialize(tokens);
    TEST_ASSERT(!serialized.empty(), "serialize non-empty");
    TEST_ASSERT(serialized.find("[keyword:int]") != std::string::npos, "serialized contains keyword");

    // 多行
    auto tokens4 = TokenParser::tokenize("int a\nint b\nint c");
    auto last = tokens4.back();
    TEST_ASSERT(last.line == 3, "multiline line tracking");
}

static void test_event_bus() {
    printf("[TEST] EventBus (std::function/lambda/std::any)\n");

    EventBus bus;
    int click_count = 0;
    int data_sum = 0;
    std::string last_event;

    auto sub1 = bus.subscribe("click", [&](const std::string &name, const std::any &data) {
        click_count++;
        last_event = name;
        if (data.type() == typeid(int))
            data_sum += std::any_cast<int>(data);
    });

    auto sub2 = bus.subscribe("click", [&](const std::string &, const std::any &data) {
        if (data.type() == typeid(int))
            data_sum += std::any_cast<int>(data) * 2;
    });

    auto sub3 = bus.subscribe("resize", [&](const std::string &name, const std::any &) {
        last_event = name;
    });

    TEST_ASSERT(bus.subscriber_count("click") == 2, "2 click subscribers");
    TEST_ASSERT(bus.subscriber_count("resize") == 1, "1 resize subscriber");

    int n = bus.emit("click", 10);
    TEST_ASSERT(n == 2, "2 handlers called");
    TEST_ASSERT(click_count == 1, "click_count incremented");
    TEST_ASSERT(data_sum == 30, "data_sum = 10 + 10*2");

    bus.emit("click", 5);
    TEST_ASSERT(data_sum == 45, "accumulated data_sum");

    bus.unsubscribe(sub2);
    TEST_ASSERT(bus.subscriber_count("click") == 1, "1 click after unsub");

    bus.emit("click", 3);
    TEST_ASSERT(data_sum == 48, "only sub1 handler");

    bus.emit("resize", std::string("800x600"));
    TEST_ASSERT(last_event == "resize", "resize event fired");

    TEST_ASSERT(bus.log().size() == 4, "4 events in log");
}

static void test_lru_cache() {
    printf("[TEST] LRU Cache (list/unordered_map)\n");

    LRUCache<std::string, int> cache(3);

    cache.put("a", 1);
    cache.put("b", 2);
    cache.put("c", 3);
    TEST_ASSERT(cache.size() == 3, "cache size 3");

    auto v = cache.get("a");
    TEST_ASSERT(v.has_value() && *v == 1, "get a = 1");

    // 插入 d，应该淘汰 b（a 刚被访问过，c 在 a 之前）
    cache.put("d", 4);
    TEST_ASSERT(cache.size() == 3, "still size 3 after eviction");
    TEST_ASSERT(!cache.get("b").has_value(), "b evicted");
    TEST_ASSERT(cache.get("a").has_value(), "a still present");
    TEST_ASSERT(cache.get("d").has_value(), "d present");

    // 更新已有 key
    cache.put("c", 30);
    v = cache.get("c");
    TEST_ASSERT(v.has_value() && *v == 30, "c updated to 30");

    TEST_ASSERT(cache.hits() > 0, "has cache hits");
    TEST_ASSERT(cache.misses() > 0, "has cache misses");
    TEST_ASSERT(cache.hit_rate() > 0.0 && cache.hit_rate() < 1.0, "hit rate in range");
}

static void test_graph() {
    printf("[TEST] Graph (deque BFS / priority_queue Dijkstra)\n");

    Graph g;
    g.add_edge("A", "B", 4);
    g.add_edge("A", "C", 2);
    g.add_edge("B", "D", 3);
    g.add_edge("C", "B", 1);
    g.add_edge("C", "D", 5);
    g.add_edge("D", "E", 1);
    g.add_edge("B", "E", 7);

    TEST_ASSERT(g.node_count() == 5, "5 nodes");

    auto bfs_order = g.bfs("A");
    TEST_ASSERT(bfs_order.size() == 5, "BFS visits all 5 nodes");
    TEST_ASSERT(bfs_order[0] == "A", "BFS starts at A");

    auto dist = g.dijkstra("A");
    TEST_ASSERT(dist["A"] == 0, "dist A->A = 0");
    TEST_ASSERT(dist["C"] == 2, "dist A->C = 2");
    TEST_ASSERT(dist["B"] == 3, "dist A->B = 3 (via C)");
    TEST_ASSERT(dist["D"] == 6, "dist A->D = 6 (A->C->B->D)");
    TEST_ASSERT(dist["E"] == 7, "dist A->E = 7 (A->C->B->D->E)");
}

static void test_json_variant() {
    printf("[TEST] JSON variant (std::variant/std::visit/shared_ptr)\n");

    using namespace json;

    // 构建: {"name": "NiPass", "version": 2.0, "features": [true, null, 42], "active": true}
    auto obj = std::make_shared<Object>();
    obj->fields["name"] = String{"NiPass"};
    obj->fields["version"] = Number{2.0};

    auto arr = std::make_shared<Array>();
    arr->elements.push_back(Bool{true});
    arr->elements.push_back(Null{});
    arr->elements.push_back(Number{42});
    obj->fields["features"] = arr;
    obj->fields["active"] = Bool{true};

    Value root = obj;
    auto s = stringify(root);
    TEST_ASSERT(s.find("\"name\":\"NiPass\"") != std::string::npos, "json has name");
    TEST_ASSERT(s.find("\"version\":2") != std::string::npos, "json has version");
    TEST_ASSERT(s.find("[true,null,42]") != std::string::npos, "json has array");

    TEST_ASSERT(is_truthy(Bool{true}), "true is truthy");
    TEST_ASSERT(!is_truthy(Bool{false}), "false is not truthy");
    TEST_ASSERT(!is_truthy(Null{}), "null is not truthy");
    TEST_ASSERT(is_truthy(Number{1.0}), "1.0 is truthy");
    TEST_ASSERT(!is_truthy(Number{0.0}), "0.0 is not truthy");
    TEST_ASSERT(is_truthy(String{"hello"}), "non-empty string truthy");
    TEST_ASSERT(!is_truthy(String{""}), "empty string not truthy");
    TEST_ASSERT(is_truthy(root), "object is truthy");
}

static void test_algorithms() {
    printf("[TEST] STL Algorithms\n");

    // partition
    std::vector<int> nums = {1, 8, 3, 7, 2, 9, 4, 6, 5, 10};
    auto pivot = std::partition(nums.begin(), nums.end(), [](int x) { return x <= 5; });
    for (auto it = nums.begin(); it != pivot; ++it)
        TEST_ASSERT(*it <= 5, "partition: left <= 5");
    for (auto it = pivot; it != nums.end(); ++it)
        TEST_ASSERT(*it > 5, "partition: right > 5");

    // transform + accumulate
    std::vector<double> prices = {10.0, 20.0, 30.0, 40.0, 50.0};
    std::vector<double> taxed;
    std::transform(prices.begin(), prices.end(), std::back_inserter(taxed),
        [](double p) { return p * 1.08; }); // 8% tax
    double total = std::accumulate(taxed.begin(), taxed.end(), 0.0);
    TEST_ASSERT(total > 161.9 && total < 162.1, "taxed total ~162.0");

    // remove_if + erase
    std::vector<std::string> words = {"hello", "", "world", "", "foo", "bar", ""};
    words.erase(std::remove_if(words.begin(), words.end(),
        [](const std::string &s) { return s.empty(); }), words.end());
    TEST_ASSERT(words.size() == 4, "removed empty strings");

    // unique
    std::vector<int> dups = {1, 1, 2, 3, 3, 3, 4, 5, 5};
    dups.erase(std::unique(dups.begin(), dups.end()), dups.end());
    TEST_ASSERT(dups.size() == 5, "unique removes duplicates");

    // nth_element (median)
    std::vector<int> data = {9, 1, 5, 3, 7, 2, 8, 4, 6};
    std::nth_element(data.begin(), data.begin() + 4, data.end());
    TEST_ASSERT(data[4] == 5, "median is 5");

    // min/max_element
    std::vector<int> vals = {42, 17, 99, 3, 55};
    auto [mn, mx] = std::minmax_element(vals.begin(), vals.end());
    TEST_ASSERT(*mn == 3 && *mx == 99, "min=3 max=99");

    // tuple + structured bindings
    std::vector<std::tuple<std::string, int, double>> records = {
        {"alice", 30, 85000.0}, {"bob", 25, 72000.0}, {"charlie", 35, 95000.0}
    };
    std::sort(records.begin(), records.end(),
        [](const auto &a, const auto &b) { return std::get<2>(a) > std::get<2>(b); });
    TEST_ASSERT(std::get<0>(records[0]) == "charlie", "highest salary first");
}

static void test_string_constants() {
    printf("[TEST] String Constants Visibility\n");

    TEST_ASSERT(strlen(DB_CONNECTION_STR) > 20, "db conn string present");
    TEST_ASSERT(strlen(REDIS_AUTH_TOKEN) > 20, "redis token present");
    TEST_ASSERT(strlen(JWT_SIGNING_KEY) > 20, "jwt key present");
    // ENCRYPTION_IV 以 \x00 开头，strlen 遇到 null 会返回 0
    // 使用 memcmp 验证完整的 16 字节内容
    {
        const char expected_iv[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
        TEST_ASSERT(memcmp(ENCRYPTION_IV, expected_iv, 16) == 0, "encryption iv 16 bytes");
    }

    TEST_ASSERT(std::string(DB_CONNECTION_STR).find("nipass.internal") != std::string::npos,
                "db conn content");
    TEST_ASSERT(std::string(REDIS_AUTH_TOKEN).find("Rds$2024") != std::string::npos,
                "redis token content");
    TEST_ASSERT(std::string(JWT_SIGNING_KEY).find("HS256") != std::string::npos,
                "jwt key content");
}

/* ========================================================================
 * main
 * ======================================================================== */

int main() {
    printf("========================================\n");
    printf("  NiPass STL Test Suite (C++)\n");
    printf("========================================\n\n");

    test_order_book();
    test_tokenizer();
    test_event_bus();
    test_lru_cache();
    test_graph();
    test_json_variant();
    test_algorithms();
    test_string_constants();

    printf("\n========================================\n");
    printf("  Results: %d/%d passed", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        printf(", %d FAILED", g_tests_failed);
    printf("\n========================================\n");

    return g_tests_failed > 0 ? 1 : 0;
}
