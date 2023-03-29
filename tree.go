// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// at https://github.com/julienschmidt/httprouter/blob/master/LICENSE

package gin

import (
	"bytes"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin/internal/bytesconv"
)

var (
	strColon = []byte(":")
	strStar  = []byte("*")
	strSlash = []byte("/")
)

// Param is a single URL parameter, consisting of a key and a value.
type Param struct {
	Key   string
	Value string
}

// Params is a Param-slice, as returned by the router.
// The slice is ordered, the first URL parameter is also the first slice value.
// It is therefore safe to read values by the index.
// NOTE: URL路径参数
type Params []Param

// Get returns the value of the first Param which key matches the given name and a boolean true.
// If no matching Param is found, an empty string is returned and a boolean false .
func (ps Params) Get(name string) (string, bool) {
	for _, entry := range ps {
		if entry.Key == name {
			return entry.Value, true
		}
	}
	return "", false
}

// ByName returns the value of the first Param which key matches the given name.
// If no matching Param is found, an empty string is returned.
func (ps Params) ByName(name string) (va string) {
	va, _ = ps.Get(name)
	return
}

// NOTE: 路由树结构
type methodTree struct {
	method string
	root   *node // 该方法对应的路由树的根节点
}

type methodTrees []methodTree

func (trees methodTrees) get(method string) *node {
	for _, tree := range trees {
		if tree.method == method {
			return tree.root
		}
	}
	return nil
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func longestCommonPrefix(a, b string) int {
	i := 0
	max := min(len(a), len(b))
	for i < max && a[i] == b[i] {
		i++
	}
	return i
}

// addChild will add a child node, keeping wildcardChild at the end
func (n *node) addChild(child *node) {
	// 如果已经有通配节点，新增子节点时需保证通配节点始终保持在最后
	if n.wildChild && len(n.children) > 0 {
		wildcardChild := n.children[len(n.children)-1]
		n.children = append(n.children[:len(n.children)-1], child, wildcardChild)
	} else {
		// 一般情况下直接新增节点即可
		n.children = append(n.children, child)
	}
}

func countParams(path string) uint16 {
	var n uint16
	s := bytesconv.StringToBytes(path)
	n += uint16(bytes.Count(s, strColon))
	n += uint16(bytes.Count(s, strStar))
	return n
}

func countSections(path string) uint16 {
	s := bytesconv.StringToBytes(path)
	return uint16(bytes.Count(s, strSlash))
}

type nodeType uint8

const (
	static nodeType = iota
	root
	param
	catchAll
)

// NOTE: 前缀树节点
type node struct {
	// 节点路径(不包含父节点)
	path string
	// 每个子节点path的首字母拼接的字符串，如search和support，子节点路径为earch和upport，则保存eu
	indices string
	// 子节点是否是通配节点类型
	wildChild bool
	// 节点类型: root(根节点)、static(静态节点)、catchAll(通配符*匹配的节点)、param(参数节点,即通配符:匹配的节点)
	nType nodeType
	// 当前节点及其子节点上注册的handler数作为其优先级，好处是:
	// 1. 包含路径越多，越先被评估，可以让包含路由多的节点先被定位
	// 2. 最长的路径一般需要花费更长的时间来定位，如果最长路径的节点能被优先评估（即每次拿子节点都命中），那么所花时间不一定比短路径的路由长
	priority uint32
	// 子节点数组
	children []*node // child nodes, at most 1 :param style node at the end of the array
	// 处理函数链(只有当前节点为叶子节点时才会有，其他情况为nil)
	handlers HandlersChain
	// 完整路径(路由树结构中根节点到当前节点的路径上的全部path的完整拼接)
	fullPath string
}

// Increments priority of the given child and reorders if necessary
func (n *node) incrementChildPrio(pos int) int {
	// 子节点数组
	cs := n.children
	// 增加对应的子节点的优先级
	cs[pos].priority++
	prio := cs[pos].priority

	// 调整节点位置，确保整个子节点数组是按照优先级倒序排列的，从而优先级更大的节点会被优先匹配
	newPos := pos
	for ; newPos > 0 && cs[newPos-1].priority < prio; newPos-- {
		// Swap node positions
		cs[newPos-1], cs[newPos] = cs[newPos], cs[newPos-1]
	}

	// 调整前缀字符串，确保每个字母和子节点数组路径的首字母一致
	if newPos != pos {
		n.indices = n.indices[:newPos] + // Unchanged prefix, might be empty
			n.indices[pos:pos+1] + // The index char we move
			n.indices[newPos:pos] + n.indices[pos+1:] // Rest without char at 'pos'
	}

	return newPos
}

// addRoute adds a node with the given handle to the path.
// Not concurrency-safe!
// 添加路由
func (n *node) addRoute(path string, handlers HandlersChain) {
	fullPath := path
	// 每新增一个节点经过此路由，当前节点优先级增加1
	n.priority++

	// 当前节点还没有注册路由且子节点数为0(未注册过路由)，直接插入新路由即可(因为这种不可能有公共前缀)
	if len(n.path) == 0 && len(n.children) == 0 {
		n.insertChild(path, fullPath, handlers)
		n.nType = root
		return
	}

	parentFullPathIndex := 0

walk:
	for {
		// 计算当前节点路径和新注册路由的最长公共前缀长度
		i := longestCommonPrefix(path, n.path)

		// 最长公共前缀长度小于当前节点的路由长度，表明当前节点需要分裂
		// 比如一开始node.path是search，新路由为support，则s是公共前缀字符串，search需要分裂为s和earch(s作为当前节点的新路径，新增earch节点)
		if i < len(n.path) {
			// 这里child节点的路径是earch
			child := node{
				// 原本父节点路径中不在最长前缀的部分(即原节点的后半部分)作为子节点
				path:      n.path[i:],
				wildChild: n.wildChild,
				nType:     static,
				indices:   n.indices,
				children:  n.children, // 继承新增路由前父节点的全部子节点
				handlers:  n.handlers, // search的处理器链转移给earch
				// 新路由support注册时，search的优先级加1了，由于earch需要降级为子节点，所以优先级要减一
				priority: n.priority - 1,
				fullPath: n.fullPath, // 继承父节点的完整路径
			}

			// 先添加子节点: (当前节点，此时还没分裂)search -> upport
			n.children = []*node{&child}
			// 设置child节点(路径为earch)的首字母e到indices中
			n.indices = bytesconv.BytesToString([]byte{n.path[i]})
			// 将原本的节点路径中公共前缀部分作为当前节点的新节点路径，即search调整为s
			n.path = path[:i]
			// 当前节点路径从search调整为s后，不再是完整路径了，故清空处理器链
			n.handlers = nil
			n.wildChild = false
			n.fullPath = fullPath[:parentFullPathIndex+i]
		}

		// 新加的路由中最长公共前缀之外的部分(upport)作为当前节点(s)的子节点
		if i < len(path) {
			path = path[i:] // path删除公共前缀之外的部分
			c := path[0]    // path路径首字母

			// '/' after param
			if n.nType == param && c == '/' && len(n.children) == 1 {
				parentFullPathIndex += len(n.path)
				n = n.children[0]
				n.priority++
				continue walk
			}

			// 判断当前节点的子节点和去除公共前缀后的path是否有公共前缀，只需要查看子节点path的第一个字母即可
			// 比如s的子节点是earch和upport，indices为eu
			// 如果新来的路由是super，则和upport的首字母匹配，需要继续分裂该子节点
			for i, max := 0, len(n.indices); i < max; i++ {
				if c == n.indices[i] {
					parentFullPathIndex += len(n.path)
					// 新节点和该子节点有公共前缀，因此该子节点的优先级加1
					i = n.incrementChildPrio(i)
					// 以该子节点为当前节点继续上述过程
					n = n.children[i]
					continue walk
				}
			}

			// 到这里说明，新路由(去掉公共前缀后)的首字母，和当前节点所有子节点首字母皆不同(即没有公共前缀)，此时直接将新路由(去掉公共前缀后)直接作为当前节点的字节插入即可
			if c != ':' && c != '*' && n.nType != catchAll {
				// 情况一: 新的路径是精确匹配路径(首字母不是:和*且当前节点不是通配节点)
				n.indices += bytesconv.BytesToString([]byte{c})
				child := &node{
					fullPath: fullPath,
				}
				// 添加到子节点，并更新当前节点的优先级
				n.addChild(child)
				n.incrementChildPrio(len(n.indices) - 1)
				n = child
			} else if n.wildChild {
				// 新节点是通配节点*或参数节点:或者当前节点是通配节点
				n = n.children[len(n.children)-1]
				n.priority++

				// Check if the wildcard matches
				if len(path) >= len(n.path) && n.path == path[:len(n.path)] &&
					// Adding a child to a catchAll is not possible
					n.nType != catchAll &&
					// Check for longer wildcard, e.g. :name and :names
					(len(n.path) >= len(path) || path[len(n.path)] == '/') {
					continue walk
				}

				// Wildcard conflict
				pathSeg := path
				if n.nType != catchAll {
					pathSeg = strings.SplitN(pathSeg, "/", 2)[0]
				}
				prefix := fullPath[:strings.Index(fullPath, pathSeg)] + n.path
				panic("'" + pathSeg +
					"' in new path '" + fullPath +
					"' conflicts with existing wildcard '" + n.path +
					"' in existing prefix '" + prefix +
					"'")
			}

			// 插入子节点
			n.insertChild(path, fullPath, handlers)
			return
		}

		// 到这里说明，新路径与当前节点路径的最长前缀等于当前节点路径(比如现有路由是新路由的一部分)，不允许注册这种路由
		if n.handlers != nil {
			panic("handlers are already registered for path '" + fullPath + "'")
		}

		// 注册过滤器链
		n.handlers = handlers
		n.fullPath = fullPath
		return
	}
}

// TODO: 寻找路径中通配部分，wildcard是路径带有*:的部分，i表示:或*的位置，valid表示是否是合法的路径
func findWildcard(path string) (wildcard string, i int, valid bool) {
	for start, c := range []byte(path) {
		// 寻找第一个*或:开始的位置
		if c != ':' && c != '*' {
			continue
		}

		// 找到通配符就设置valid为true，通配符的起始位置就是start
		valid = true
		// 从通配符后面继续查找
		for end, c := range []byte(path[start+1:]) {
			switch c {
			case '/':
				// 如果遇到/，则返回wildcard(比如:name/，wildcard就是name)
				return path[start : start+1+end], start, valid
			case ':', '*':
				// 一个部分只能有一个通配符，否则valid = false
				valid = false
			}
		}
		return path[start:], start, valid
	}
	return "", -1, false
}

// 这里的path是新路由中去掉前缀之后的部分
func (n *node) insertChild(path string, fullPath string, handlers HandlersChain) {
	for {
		// 寻找路径中的通配符
		wildcard, i, valid := findWildcard(path)
		// 不包含通配符
		if i < 0 {
			break
		}

		// 不合法路径(比如一个part中包含两个通配符号)
		if !valid {
			panic("only one wildcard per path segment is allowed, has: '" +
				wildcard + "' in path '" + fullPath + "'")
		}

		if len(wildcard) < 2 {
			panic("wildcards must be named with a non-empty name in path '" + fullPath + "'")
		}

		// 通配符是:,
		if wildcard[0] == ':' { // param
			if i > 0 {
				// Insert prefix before the current wildcard
				n.path = path[:i]
				path = path[i:]
			}

			// 新增通配节点作为子节点
			child := &node{
				nType:    param,
				path:     wildcard,
				fullPath: fullPath,
			}
			n.addChild(child)
			n.wildChild = true // 表示子路径有通配符
			n = child
			n.priority++

			// 如果wildcard长度小于path，说明除了wildcard外还存在其他的子路径，继续进行处理
			// 注意此时当前节点变成了上面创建的通配子节点
			if len(wildcard) < len(path) {
				path = path[len(wildcard):]

				child := &node{
					priority: 1,
					fullPath: fullPath,
				}
				n.addChild(child)
				n = child
				continue
			}

			// 执行到此说明上面处理的通配节点是最后一个子节点(已经没有其他其他子路径要处理了)，将处理器链添加到叶节点上
			n.handlers = handlers
			return
		}

		// 带通配符*的子路径只能出现在路径最后
		if i+len(wildcard) != len(path) {
			panic("catch-all routes are only allowed at the end of the path in path '" + fullPath + "'")
		}

		if len(n.path) > 0 && n.path[len(n.path)-1] == '/' {
			pathSeg := strings.SplitN(n.children[0].path, "/", 2)[0]
			panic("catch-all wildcard '" + path +
				"' in new path '" + fullPath +
				"' conflicts with existing path segment '" + pathSeg +
				"' in existing prefix '" + n.path + pathSeg +
				"'")
		}

		// 通配符*的前一个字符必须是/
		i--
		if path[i] != '/' {
			panic("no / before catch-all in path '" + fullPath + "'")
		}

		// 当前节点的路径设置为*之前的路径
		n.path = path[:i]

		// 先在当前节点下挂一个带空path的子节点
		child := &node{
			wildChild: true,
			nType:     catchAll,
			fullPath:  fullPath,
		}

		// 添加子节点
		n.addChild(child)
		// 通配节点的indiced字符设置为/
		n.indices = string('/')
		// 当前节点下沉为上面的子节点
		n = child
		n.priority++

		// 再在上述子节点下挂一个catchAll节点
		child = &node{
			path:     path[i:],
			nType:    catchAll,
			handlers: handlers,
			priority: 1,
			fullPath: fullPath,
		}
		n.children = []*node{child}

		return
	}

	// 不包含通配符，直接插入
	n.path = path
	n.handlers = handlers
	n.fullPath = fullPath
}

// nodeValue holds return values of (*Node).getValue method
type nodeValue struct {
	handlers HandlersChain // 处理器函数链
	params   *Params
	tsr      bool
	fullPath string
}

type skippedNode struct {
	path        string
	node        *node
	paramsCount int16
}

// Returns the handle registered with the given path (key). The values of
// wildcards are saved to a map.
// If no handle can be found, a TSR (trailing slash redirect) recommendation is
// made if a handle exists with an extra (without the) trailing slash for the
// given path.
// NOTE: 从路由树中获取path对应的节点
func (n *node) getValue(path string, params *Params, skippedNodes *[]skippedNode, unescape bool) (value nodeValue) {
	var globalParamsCount int16

walk: // Outer loop for walking the tree
	for {
		prefix := n.path
		// 待匹配路径长度大于当前节点路径
		if len(path) > len(prefix) {
			if path[:len(prefix)] == prefix {
				// path取prefix之后的部分(即不包括当前节点路径)
				path = path[len(prefix):]

				// 遍历当前节点的indice，尝试找出和path首字符匹配的子节点
				idxc := path[0]
				for i, c := range []byte(n.indices) {
					// 匹配到非通配节点
					if c == idxc {
						//  strings.HasPrefix(n.children[len(n.children)-1].path, ":") == n.wildChild
						if n.wildChild {
							index := len(*skippedNodes)
							*skippedNodes = (*skippedNodes)[:index+1]
							(*skippedNodes)[index] = skippedNode{
								path: prefix + path,
								node: &node{
									path:      n.path,
									wildChild: n.wildChild,
									nType:     n.nType,
									priority:  n.priority,
									children:  n.children,
									handlers:  n.handlers,
									fullPath:  n.fullPath,
								},
								paramsCount: globalParamsCount,
							}
						}
						// 以该子节点为当前节点进行下一轮匹配
						n = n.children[i]
						continue walk
					}
				}

				if !n.wildChild {
					// If the path at the end of the loop is not equal to '/' and the current node has no child nodes
					// the current node needs to roll back to last valid skippedNode
					if path != "/" {
						for length := len(*skippedNodes); length > 0; length-- {
							skippedNode := (*skippedNodes)[length-1]
							*skippedNodes = (*skippedNodes)[:length-1]
							if strings.HasSuffix(skippedNode.path, path) {
								path = skippedNode.path
								n = skippedNode.node
								if value.params != nil {
									*value.params = (*value.params)[:skippedNode.paramsCount]
								}
								globalParamsCount = skippedNode.paramsCount
								continue walk
							}
						}
					}

					// Nothing found.
					// We can recommend to redirect to the same URL without a
					// trailing slash if a leaf exists for that path.
					value.tsr = path == "/" && n.handlers != nil
					return
				}

				// Handle wildcard child, which is always at the end of the array
				n = n.children[len(n.children)-1]
				globalParamsCount++

				switch n.nType {
				case param:
					// fix truncate the parameter
					// tree_test.go  line: 204

					// Find param end (either '/' or path end)
					end := 0
					for end < len(path) && path[end] != '/' {
						end++
					}

					// Save param value
					if params != nil && cap(*params) > 0 {
						if value.params == nil {
							value.params = params
						}
						// Expand slice within preallocated capacity
						i := len(*value.params)
						*value.params = (*value.params)[:i+1]
						val := path[:end]
						if unescape {
							if v, err := url.QueryUnescape(val); err == nil {
								val = v
							}
						}
						(*value.params)[i] = Param{
							Key:   n.path[1:],
							Value: val,
						}
					}

					// we need to go deeper!
					if end < len(path) {
						if len(n.children) > 0 {
							path = path[end:]
							n = n.children[0]
							continue walk
						}

						// ... but we can't
						value.tsr = len(path) == end+1
						return
					}

					if value.handlers = n.handlers; value.handlers != nil {
						value.fullPath = n.fullPath
						return
					}
					if len(n.children) == 1 {
						// No handle found. Check if a handle for this path + a
						// trailing slash exists for TSR recommendation
						n = n.children[0]
						value.tsr = (n.path == "/" && n.handlers != nil) || (n.path == "" && n.indices == "/")
					}
					return

				case catchAll:
					// Save param value
					if params != nil {
						if value.params == nil {
							value.params = params
						}
						// Expand slice within preallocated capacity
						i := len(*value.params)
						*value.params = (*value.params)[:i+1]
						val := path
						if unescape {
							if v, err := url.QueryUnescape(path); err == nil {
								val = v
							}
						}
						(*value.params)[i] = Param{
							Key:   n.path[2:],
							Value: val,
						}
					}

					value.handlers = n.handlers
					value.fullPath = n.fullPath
					return

				default:
					panic("invalid node type")
				}
			}
		}

		// path等于node.path，说明已经找到目标
		if path == prefix {
			// If the current path does not equal '/' and the node does not have a registered handle and the most recently matched node has a child node
			// the current node needs to roll back to last valid skippedNode
			// 返回handlers
			if n.handlers == nil && path != "/" {
				for length := len(*skippedNodes); length > 0; length-- {
					skippedNode := (*skippedNodes)[length-1]
					*skippedNodes = (*skippedNodes)[:length-1]
					if strings.HasSuffix(skippedNode.path, path) {
						path = skippedNode.path
						n = skippedNode.node
						if value.params != nil {
							*value.params = (*value.params)[:skippedNode.paramsCount]
						}
						globalParamsCount = skippedNode.paramsCount
						continue walk
					}
				}
				//	n = latestNode.children[len(latestNode.children)-1]
			}
			// We should have reached the node containing the handle.
			// Check if this node has a handle registered.
			if value.handlers = n.handlers; value.handlers != nil {
				value.fullPath = n.fullPath
				return
			}

			// If there is no handle for this route, but this route has a
			// wildcard child, there must be a handle for this path with an
			// additional trailing slash
			if path == "/" && n.wildChild && n.nType != root {
				value.tsr = true
				return
			}

			if path == "/" && n.nType == static {
				value.tsr = true
				return
			}

			// No handle found. Check if a handle for this path + a
			// trailing slash exists for trailing slash recommendation
			for i, c := range []byte(n.indices) {
				if c == '/' {
					n = n.children[i]
					value.tsr = (len(n.path) == 1 && n.handlers != nil) ||
						(n.nType == catchAll && n.children[0].handlers != nil)
					return
				}
			}

			return
		}

		// Nothing found. We can recommend to redirect to the same URL with an
		// extra trailing slash if a leaf exists for that path
		// path 与 node.path 已经没有公共前缀，说明匹配失败
		value.tsr = path == "/" ||
			(len(prefix) == len(path)+1 && prefix[len(path)] == '/' &&
				path == prefix[:len(prefix)-1] && n.handlers != nil)

		// roll back to last valid skippedNode
		if !value.tsr && path != "/" {
			for length := len(*skippedNodes); length > 0; length-- {
				skippedNode := (*skippedNodes)[length-1]
				*skippedNodes = (*skippedNodes)[:length-1]
				if strings.HasSuffix(skippedNode.path, path) {
					path = skippedNode.path
					n = skippedNode.node
					if value.params != nil {
						*value.params = (*value.params)[:skippedNode.paramsCount]
					}
					globalParamsCount = skippedNode.paramsCount
					continue walk
				}
			}
		}

		return
	}
}

// Makes a case-insensitive lookup of the given path and tries to find a handler.
// It can optionally also fix trailing slashes.
// It returns the case-corrected path and a bool indicating whether the lookup
// was successful.
func (n *node) findCaseInsensitivePath(path string, fixTrailingSlash bool) ([]byte, bool) {
	const stackBufSize = 128

	// Use a static sized buffer on the stack in the common case.
	// If the path is too long, allocate a buffer on the heap instead.
	buf := make([]byte, 0, stackBufSize)
	if length := len(path) + 1; length > stackBufSize {
		buf = make([]byte, 0, length)
	}

	ciPath := n.findCaseInsensitivePathRec(
		path,
		buf,       // Preallocate enough memory for new path
		[4]byte{}, // Empty rune buffer
		fixTrailingSlash,
	)

	return ciPath, ciPath != nil
}

// Shift bytes in array by n bytes left
func shiftNRuneBytes(rb [4]byte, n int) [4]byte {
	switch n {
	case 0:
		return rb
	case 1:
		return [4]byte{rb[1], rb[2], rb[3], 0}
	case 2:
		return [4]byte{rb[2], rb[3]}
	case 3:
		return [4]byte{rb[3]}
	default:
		return [4]byte{}
	}
}

// Recursive case-insensitive lookup function used by n.findCaseInsensitivePath
func (n *node) findCaseInsensitivePathRec(path string, ciPath []byte, rb [4]byte, fixTrailingSlash bool) []byte {
	npLen := len(n.path)

walk: // Outer loop for walking the tree
	for len(path) >= npLen && (npLen == 0 || strings.EqualFold(path[1:npLen], n.path[1:])) {
		// Add common prefix to result
		oldPath := path
		path = path[npLen:]
		ciPath = append(ciPath, n.path...)

		if len(path) == 0 {
			// We should have reached the node containing the handle.
			// Check if this node has a handle registered.
			if n.handlers != nil {
				return ciPath
			}

			// No handle found.
			// Try to fix the path by adding a trailing slash
			if fixTrailingSlash {
				for i, c := range []byte(n.indices) {
					if c == '/' {
						n = n.children[i]
						if (len(n.path) == 1 && n.handlers != nil) ||
							(n.nType == catchAll && n.children[0].handlers != nil) {
							return append(ciPath, '/')
						}
						return nil
					}
				}
			}
			return nil
		}

		// If this node does not have a wildcard (param or catchAll) child,
		// we can just look up the next child node and continue to walk down
		// the tree
		if !n.wildChild {
			// Skip rune bytes already processed
			rb = shiftNRuneBytes(rb, npLen)

			if rb[0] != 0 {
				// Old rune not finished
				idxc := rb[0]
				for i, c := range []byte(n.indices) {
					if c == idxc {
						// continue with child node
						n = n.children[i]
						npLen = len(n.path)
						continue walk
					}
				}
			} else {
				// Process a new rune
				var rv rune

				// Find rune start.
				// Runes are up to 4 byte long,
				// -4 would definitely be another rune.
				var off int
				for max := min(npLen, 3); off < max; off++ {
					if i := npLen - off; utf8.RuneStart(oldPath[i]) {
						// read rune from cached path
						rv, _ = utf8.DecodeRuneInString(oldPath[i:])
						break
					}
				}

				// Calculate lowercase bytes of current rune
				lo := unicode.ToLower(rv)
				utf8.EncodeRune(rb[:], lo)

				// Skip already processed bytes
				rb = shiftNRuneBytes(rb, off)

				idxc := rb[0]
				for i, c := range []byte(n.indices) {
					// Lowercase matches
					if c == idxc {
						// must use a recursive approach since both the
						// uppercase byte and the lowercase byte might exist
						// as an index
						if out := n.children[i].findCaseInsensitivePathRec(
							path, ciPath, rb, fixTrailingSlash,
						); out != nil {
							return out
						}
						break
					}
				}

				// If we found no match, the same for the uppercase rune,
				// if it differs
				if up := unicode.ToUpper(rv); up != lo {
					utf8.EncodeRune(rb[:], up)
					rb = shiftNRuneBytes(rb, off)

					idxc := rb[0]
					for i, c := range []byte(n.indices) {
						// Uppercase matches
						if c == idxc {
							// Continue with child node
							n = n.children[i]
							npLen = len(n.path)
							continue walk
						}
					}
				}
			}

			// Nothing found. We can recommend to redirect to the same URL
			// without a trailing slash if a leaf exists for that path
			if fixTrailingSlash && path == "/" && n.handlers != nil {
				return ciPath
			}
			return nil
		}

		n = n.children[0]
		switch n.nType {
		case param:
			// Find param end (either '/' or path end)
			end := 0
			for end < len(path) && path[end] != '/' {
				end++
			}

			// Add param value to case insensitive path
			ciPath = append(ciPath, path[:end]...)

			// We need to go deeper!
			if end < len(path) {
				if len(n.children) > 0 {
					// Continue with child node
					n = n.children[0]
					npLen = len(n.path)
					path = path[end:]
					continue
				}

				// ... but we can't
				if fixTrailingSlash && len(path) == end+1 {
					return ciPath
				}
				return nil
			}

			if n.handlers != nil {
				return ciPath
			}

			if fixTrailingSlash && len(n.children) == 1 {
				// No handle found. Check if a handle for this path + a
				// trailing slash exists
				n = n.children[0]
				if n.path == "/" && n.handlers != nil {
					return append(ciPath, '/')
				}
			}

			return nil

		case catchAll:
			return append(ciPath, path...)

		default:
			panic("invalid node type")
		}
	}

	// Nothing found.
	// Try to fix the path by adding / removing a trailing slash
	if fixTrailingSlash {
		if path == "/" {
			return ciPath
		}
		if len(path)+1 == npLen && n.path[len(path)] == '/' &&
			strings.EqualFold(path[1:], n.path[1:len(path)]) && n.handlers != nil {
			return append(ciPath, n.path...)
		}
	}
	return nil
}
