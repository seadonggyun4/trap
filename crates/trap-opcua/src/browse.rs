// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA Node Browser implementation.
//!
//! This module provides comprehensive node browsing capabilities for OPC UA servers,
//! including recursive tree traversal, filtered browsing, and path-based navigation.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       NodeBrowser (trait)                       │
//! │            (Abstract interface for browsing operations)         │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     NodeBrowserImpl                             │
//! │              (Default implementation with caching)              │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┼───────────────────┐
//!          ▼                   ▼                   ▼
//!    BrowseOptions      BrowseResult        BrowsePath
//!    (Configuration)    (Node info)      (Path navigation)
//! ```
//!
//! # Features
//!
//! - **Configurable Browsing**: Filter by node class, reference type, direction
//! - **Recursive Traversal**: Browse entire subtrees with depth control
//! - **Path Navigation**: Find nodes by browse path (e.g., "Objects/Server/Status")
//! - **Caching Support**: Optional caching for repeated queries
//! - **Streaming Results**: Iterator-based API for large result sets
//!
//! # Examples
//!
//! ```rust,ignore
//! use trap_opcua::browse::{NodeBrowser, BrowseOptions, NodeBrowserImpl};
//!
//! // Create browser with transport
//! let browser = NodeBrowserImpl::new(transport);
//!
//! // Browse children of Objects folder
//! let children = browser.browse_children(
//!     &NodeId::OBJECTS_FOLDER,
//!     BrowseOptions::default(),
//! ).await?;
//!
//! // Browse entire tree with depth limit
//! let tree = browser.browse_tree(3).await?;
//!
//! // Find node by path
//! let node = browser.find_by_path("Objects/Server/ServerStatus").await?;
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::{BrowseError, OpcUaError, OpcUaResult};
use crate::types::{BrowseDirection, NodeClass, NodeId, OpcUaDataType};

// =============================================================================
// Standard Reference Type Node IDs (OPC UA Part 5)
// =============================================================================

/// Standard OPC UA reference type node IDs.
pub mod reference_types {
    use crate::types::{NodeId, NodeIdentifier};

    /// References (abstract base type) - i=31.
    pub fn references() -> NodeId {
        NodeId {
            namespace_index: 0,
            identifier: NodeIdentifier::Numeric(31),
        }
    }

    /// HierarchicalReferences (abstract) - i=33.
    pub fn hierarchical_references() -> NodeId {
        NodeId {
            namespace_index: 0,
            identifier: NodeIdentifier::Numeric(33),
        }
    }

    /// HasChild (abstract) - i=34.
    pub fn has_child() -> NodeId {
        NodeId {
            namespace_index: 0,
            identifier: NodeIdentifier::Numeric(34),
        }
    }

    /// Organizes - i=35.
    pub fn organizes() -> NodeId {
        NodeId {
            namespace_index: 0,
            identifier: NodeIdentifier::Numeric(35),
        }
    }

    /// HasComponent - i=47.
    pub fn has_component() -> NodeId {
        NodeId {
            namespace_index: 0,
            identifier: NodeIdentifier::Numeric(47),
        }
    }

    /// HasProperty - i=46.
    pub fn has_property() -> NodeId {
        NodeId {
            namespace_index: 0,
            identifier: NodeIdentifier::Numeric(46),
        }
    }

    /// HasTypeDefinition - i=40.
    pub fn has_type_definition() -> NodeId {
        NodeId {
            namespace_index: 0,
            identifier: NodeIdentifier::Numeric(40),
        }
    }

    /// HasSubtype - i=45.
    pub fn has_subtype() -> NodeId {
        NodeId {
            namespace_index: 0,
            identifier: NodeIdentifier::Numeric(45),
        }
    }
}

// =============================================================================
// BrowseOptions
// =============================================================================

/// Options for browse operations.
///
/// Provides fine-grained control over what nodes are returned during browsing.
///
/// # Examples
///
/// ```
/// use trap_opcua::{BrowseOptions, BrowseDirection, NodeClass};
///
/// // Browse only variables
/// let options = BrowseOptions::default()
///     .with_node_class_filter(vec![NodeClass::Variable]);
///
/// // Browse in both directions
/// let options = BrowseOptions::default()
///     .with_direction(BrowseDirection::Both);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseOptions {
    /// Browse direction.
    #[serde(default)]
    pub direction: BrowseDirection,

    /// Filter by node class (empty = all classes).
    #[serde(default)]
    pub node_class_filter: Vec<NodeClass>,

    /// Reference type to follow (None = all hierarchical references).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_type_id: Option<NodeId>,

    /// Include subtypes of the reference type.
    #[serde(default = "default_true")]
    pub include_subtypes: bool,

    /// Maximum results per browse request.
    #[serde(default = "default_max_results")]
    pub max_results_per_request: u32,

    /// Whether to include the starting node in results.
    #[serde(default)]
    pub include_start_node: bool,

    /// Maximum depth for recursive browsing (0 = unlimited).
    #[serde(default)]
    pub max_depth: usize,

    /// Node IDs to exclude from results.
    #[serde(default)]
    pub exclude_node_ids: HashSet<String>,
}

fn default_true() -> bool {
    true
}

fn default_max_results() -> u32 {
    1000
}

impl Default for BrowseOptions {
    fn default() -> Self {
        Self {
            direction: BrowseDirection::Forward,
            node_class_filter: Vec::new(),
            reference_type_id: None,
            include_subtypes: true,
            max_results_per_request: default_max_results(),
            include_start_node: false,
            max_depth: 0,
            exclude_node_ids: HashSet::new(),
        }
    }
}

impl BrowseOptions {
    /// Creates new browse options with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the browse direction.
    pub fn with_direction(mut self, direction: BrowseDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Sets the node class filter.
    pub fn with_node_class_filter(mut self, classes: Vec<NodeClass>) -> Self {
        self.node_class_filter = classes;
        self
    }

    /// Adds a node class to the filter.
    pub fn add_node_class(mut self, class: NodeClass) -> Self {
        self.node_class_filter.push(class);
        self
    }

    /// Sets the reference type to follow.
    pub fn with_reference_type(mut self, reference_type: NodeId) -> Self {
        self.reference_type_id = Some(reference_type);
        self
    }

    /// Sets whether to include subtypes.
    pub fn with_include_subtypes(mut self, include: bool) -> Self {
        self.include_subtypes = include;
        self
    }

    /// Sets the maximum results per request.
    pub fn with_max_results(mut self, max: u32) -> Self {
        self.max_results_per_request = max;
        self
    }

    /// Sets whether to include the starting node.
    pub fn with_include_start(mut self, include: bool) -> Self {
        self.include_start_node = include;
        self
    }

    /// Sets the maximum browsing depth.
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Excludes specific node IDs from results.
    pub fn with_excluded_nodes(mut self, node_ids: HashSet<String>) -> Self {
        self.exclude_node_ids = node_ids;
        self
    }

    /// Creates options for browsing only objects.
    pub fn objects_only() -> Self {
        Self::default().with_node_class_filter(vec![NodeClass::Object])
    }

    /// Creates options for browsing only variables.
    pub fn variables_only() -> Self {
        Self::default().with_node_class_filter(vec![NodeClass::Variable])
    }

    /// Creates options for browsing objects and variables.
    pub fn objects_and_variables() -> Self {
        Self::default().with_node_class_filter(vec![NodeClass::Object, NodeClass::Variable])
    }

    /// Creates options for browsing type definitions.
    pub fn types_only() -> Self {
        Self::default().with_node_class_filter(vec![
            NodeClass::ObjectType,
            NodeClass::VariableType,
            NodeClass::ReferenceType,
            NodeClass::DataType,
        ])
    }

    /// Returns the node class mask for OPC UA browse request.
    pub fn node_class_mask(&self) -> u32 {
        if self.node_class_filter.is_empty() {
            0xFF // All classes
        } else {
            self.node_class_filter.iter().map(|c| c.value()).fold(0, |acc, v| acc | v)
        }
    }

    /// Checks if a node class matches the filter.
    pub fn matches_node_class(&self, class: NodeClass) -> bool {
        self.node_class_filter.is_empty() || self.node_class_filter.contains(&class)
    }

    /// Checks if a node ID is excluded.
    pub fn is_excluded(&self, node_id: &NodeId) -> bool {
        self.exclude_node_ids.contains(&node_id.to_string())
    }
}

// =============================================================================
// BrowseNode
// =============================================================================

/// Comprehensive information about a browsed node.
///
/// Contains all relevant metadata retrieved during a browse operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseNode {
    /// The node ID.
    pub node_id: NodeId,

    /// The browse name (namespace qualified).
    pub browse_name: QualifiedName,

    /// The display name (localized).
    pub display_name: String,

    /// The node class.
    pub node_class: NodeClass,

    /// Description (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Data type (for Variable nodes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<OpcUaDataType>,

    /// Type definition node ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_definition: Option<NodeId>,

    /// Reference type from parent to this node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_type: Option<NodeId>,

    /// Whether the node is writable (for Variable nodes).
    #[serde(default)]
    pub writable: bool,

    /// Whether the node has children.
    #[serde(default)]
    pub has_children: bool,

    /// Child nodes (populated during recursive browse).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<BrowseNode>,

    /// Path from root to this node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,

    /// Depth in the browse tree.
    #[serde(default)]
    pub depth: usize,
}

impl BrowseNode {
    /// Creates a new browse node with minimal information.
    pub fn new(node_id: NodeId, browse_name: QualifiedName, display_name: String, node_class: NodeClass) -> Self {
        Self {
            node_id,
            browse_name,
            display_name,
            node_class,
            description: None,
            data_type: None,
            type_definition: None,
            reference_type: None,
            writable: false,
            has_children: false,
            children: Vec::new(),
            path: Vec::new(),
            depth: 0,
        }
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the data type.
    pub fn with_data_type(mut self, data_type: OpcUaDataType) -> Self {
        self.data_type = Some(data_type);
        self
    }

    /// Sets the type definition.
    pub fn with_type_definition(mut self, type_def: NodeId) -> Self {
        self.type_definition = Some(type_def);
        self
    }

    /// Sets the reference type.
    pub fn with_reference_type(mut self, ref_type: NodeId) -> Self {
        self.reference_type = Some(ref_type);
        self
    }

    /// Sets the writable flag.
    pub fn with_writable(mut self, writable: bool) -> Self {
        self.writable = writable;
        self
    }

    /// Sets the path.
    pub fn with_path(mut self, path: Vec<String>) -> Self {
        self.path = path;
        self
    }

    /// Sets the depth.
    pub fn with_depth(mut self, depth: usize) -> Self {
        self.depth = depth;
        self
    }

    /// Adds a child node.
    pub fn add_child(&mut self, child: BrowseNode) {
        self.has_children = true;
        self.children.push(child);
    }

    /// Returns the full path as a string.
    pub fn full_path(&self) -> String {
        if self.path.is_empty() {
            self.display_name.clone()
        } else {
            format!("{}/{}", self.path.join("/"), self.display_name)
        }
    }

    /// Returns `true` if this node can have a value (is a Variable).
    pub fn has_value(&self) -> bool {
        self.node_class == NodeClass::Variable
    }

    /// Returns `true` if this node is browsable (is an Object).
    pub fn is_browsable(&self) -> bool {
        matches!(self.node_class, NodeClass::Object | NodeClass::View)
    }

    /// Converts to trap_core::AddressInfo.
    pub fn to_address_info(&self) -> trap_core::address::AddressInfo {
        let address = trap_core::Address::OpcUa(self.node_id.to_core_node_id());

        let mut info = trap_core::address::AddressInfo::new(address, &self.display_name);

        if let Some(ref desc) = self.description {
            info = info.with_description(desc);
        }

        if let Some(ref dt) = self.data_type {
            info = info.with_data_type(dt.name());
        }

        info = info.with_writable(self.writable);

        info
    }
}

impl fmt::Display for BrowseNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {} ({})", self.node_class, self.display_name, self.node_id)
    }
}

// =============================================================================
// QualifiedName
// =============================================================================

/// OPC UA qualified name (namespace index + name).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QualifiedName {
    /// Namespace index.
    pub namespace_index: u16,

    /// The name string.
    pub name: String,
}

impl QualifiedName {
    /// Creates a new qualified name.
    pub fn new(namespace_index: u16, name: impl Into<String>) -> Self {
        Self {
            namespace_index,
            name: name.into(),
        }
    }

    /// Creates a qualified name in namespace 0.
    pub fn standard(name: impl Into<String>) -> Self {
        Self::new(0, name)
    }

    /// Returns the string representation.
    pub fn to_string_with_ns(&self) -> String {
        if self.namespace_index == 0 {
            self.name.clone()
        } else {
            format!("{}:{}", self.namespace_index, self.name)
        }
    }
}

impl fmt::Display for QualifiedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_with_ns())
    }
}

impl From<&str> for QualifiedName {
    fn from(s: &str) -> Self {
        if let Some((ns, name)) = s.split_once(':') {
            if let Ok(ns_idx) = ns.parse::<u16>() {
                return Self::new(ns_idx, name);
            }
        }
        Self::standard(s)
    }
}

// =============================================================================
// BrowsePath
// =============================================================================

/// A browse path for navigating to a specific node.
///
/// Browse paths allow finding nodes by their hierarchical path rather than
/// by node ID. This is useful when the node ID structure is not known.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowsePath {
    /// Starting node (usually Objects folder).
    pub start_node: NodeId,

    /// Path segments to follow.
    pub segments: Vec<BrowsePathSegment>,
}

impl BrowsePath {
    /// Creates a new browse path from the Objects folder.
    pub fn from_objects(segments: Vec<BrowsePathSegment>) -> Self {
        Self {
            start_node: NodeId::OBJECTS_FOLDER.clone(),
            segments,
        }
    }

    /// Creates a browse path from a path string (e.g., "Objects/Server/Status").
    ///
    /// The first segment must be "Objects" or "Root".
    pub fn from_string(path: &str) -> OpcUaResult<Self> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return Err(OpcUaError::browse(BrowseError::InvalidPath {
                path: path.to_string(),
                reason: "Empty path".to_string(),
            }));
        }

        let (start_node, skip) = match parts[0].to_lowercase().as_str() {
            "objects" => (NodeId::OBJECTS_FOLDER.clone(), 1),
            "root" => (NodeId::ROOT_FOLDER.clone(), 1),
            "types" => (NodeId::TYPES_FOLDER.clone(), 1),
            "views" => (NodeId::VIEWS_FOLDER.clone(), 1),
            _ => (NodeId::OBJECTS_FOLDER.clone(), 0),
        };

        let segments = parts
            .iter()
            .skip(skip)
            .map(|name| BrowsePathSegment::new(QualifiedName::from(*name)))
            .collect();

        Ok(Self { start_node, segments })
    }

    /// Creates a new browse path with a custom start node.
    pub fn new(start_node: NodeId, segments: Vec<BrowsePathSegment>) -> Self {
        Self { start_node, segments }
    }

    /// Returns `true` if the path is empty.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the number of segments.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Appends a segment to the path.
    pub fn push(&mut self, segment: BrowsePathSegment) {
        self.segments.push(segment);
    }

    /// Returns the path as a string.
    pub fn to_path_string(&self) -> String {
        self.segments
            .iter()
            .map(|s| s.target_name.name.as_str())
            .collect::<Vec<_>>()
            .join("/")
    }
}

impl fmt::Display for BrowsePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_path_string())
    }
}

// =============================================================================
// BrowsePathSegment
// =============================================================================

/// A single segment in a browse path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowsePathSegment {
    /// Reference type to follow (None = any hierarchical reference).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_type_id: Option<NodeId>,

    /// Whether to include subtypes of the reference type.
    #[serde(default = "default_true")]
    pub include_subtypes: bool,

    /// Target browse name to find.
    pub target_name: QualifiedName,
}

impl BrowsePathSegment {
    /// Creates a new path segment.
    pub fn new(target_name: QualifiedName) -> Self {
        Self {
            reference_type_id: None,
            include_subtypes: true,
            target_name,
        }
    }

    /// Creates a segment with a specific reference type.
    pub fn with_reference_type(mut self, reference_type: NodeId) -> Self {
        self.reference_type_id = Some(reference_type);
        self
    }

    /// Sets whether to include subtypes.
    pub fn with_include_subtypes(mut self, include: bool) -> Self {
        self.include_subtypes = include;
        self
    }

    /// Checks if a node matches this segment.
    pub fn matches(&self, browse_name: &QualifiedName) -> bool {
        // Match by name (namespace 0 matches any namespace)
        if self.target_name.namespace_index == 0 {
            self.target_name.name == browse_name.name
        } else {
            self.target_name == *browse_name
        }
    }
}

// =============================================================================
// BrowseTreeConfig
// =============================================================================

/// Configuration for tree browsing operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseTreeConfig {
    /// Maximum depth to browse (0 = unlimited).
    pub max_depth: usize,

    /// Maximum total nodes to return.
    pub max_nodes: usize,

    /// Node classes to include.
    pub node_classes: Vec<NodeClass>,

    /// Whether to read additional attributes.
    pub read_attributes: bool,

    /// Namespaces to include (empty = all).
    pub namespaces: Vec<u16>,

    /// Whether to follow type references.
    pub follow_type_references: bool,
}

impl Default for BrowseTreeConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_nodes: 10000,
            node_classes: vec![NodeClass::Object, NodeClass::Variable],
            read_attributes: false,
            namespaces: Vec::new(),
            follow_type_references: false,
        }
    }
}

impl BrowseTreeConfig {
    /// Creates a shallow browse (depth 1).
    pub fn shallow() -> Self {
        Self {
            max_depth: 1,
            max_nodes: 1000,
            ..Default::default()
        }
    }

    /// Creates a deep browse with all node classes.
    pub fn deep() -> Self {
        Self {
            max_depth: 10,
            max_nodes: 50000,
            node_classes: Vec::new(), // All classes
            read_attributes: true,
            ..Default::default()
        }
    }

    /// Sets the maximum depth.
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Sets the maximum nodes.
    pub fn with_max_nodes(mut self, nodes: usize) -> Self {
        self.max_nodes = nodes;
        self
    }

    /// Sets the node classes to include.
    pub fn with_node_classes(mut self, classes: Vec<NodeClass>) -> Self {
        self.node_classes = classes;
        self
    }

    /// Sets whether to read additional attributes.
    pub fn with_read_attributes(mut self, read: bool) -> Self {
        self.read_attributes = read;
        self
    }

    /// Returns browse options for this configuration.
    pub fn to_browse_options(&self) -> BrowseOptions {
        BrowseOptions::default()
            .with_node_class_filter(self.node_classes.clone())
            .with_max_depth(self.max_depth)
    }
}

// =============================================================================
// NodeBrowser Trait
// =============================================================================

/// Abstract interface for node browsing operations.
///
/// This trait defines the core browsing capabilities that any browser
/// implementation must provide.
#[async_trait]
pub trait NodeBrowser: Send + Sync {
    /// Browses the direct children of a node.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to browse from
    /// * `options` - Browse options
    ///
    /// # Returns
    ///
    /// A vector of child nodes.
    async fn browse_children(
        &self,
        node_id: &NodeId,
        options: BrowseOptions,
    ) -> OpcUaResult<Vec<BrowseNode>>;

    /// Browses a complete subtree recursively.
    ///
    /// # Arguments
    ///
    /// * `root_id` - The root node to start from
    /// * `config` - Tree browsing configuration
    ///
    /// # Returns
    ///
    /// The root node with all children populated.
    async fn browse_tree(
        &self,
        root_id: &NodeId,
        config: BrowseTreeConfig,
    ) -> OpcUaResult<BrowseNode>;

    /// Finds a node by browse path.
    ///
    /// # Arguments
    ///
    /// * `path` - The browse path to follow
    ///
    /// # Returns
    ///
    /// The target node if found.
    async fn find_by_path(&self, path: &BrowsePath) -> OpcUaResult<Option<BrowseNode>>;

    /// Finds a node by string path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path string (e.g., "Objects/Server/Status")
    ///
    /// # Returns
    ///
    /// The target node if found.
    async fn find_by_string_path(&self, path: &str) -> OpcUaResult<Option<BrowseNode>> {
        let browse_path = BrowsePath::from_string(path)?;
        self.find_by_path(&browse_path).await
    }

    /// Gets detailed information about a specific node.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node to get information about
    ///
    /// # Returns
    ///
    /// Detailed node information.
    async fn get_node_info(&self, node_id: &NodeId) -> OpcUaResult<BrowseNode>;

    /// Browses all variables under a node.
    ///
    /// Convenience method for finding all readable data points.
    async fn browse_variables(
        &self,
        node_id: &NodeId,
        max_depth: usize,
    ) -> OpcUaResult<Vec<BrowseNode>> {
        let config = BrowseTreeConfig::default()
            .with_max_depth(max_depth)
            .with_node_classes(vec![NodeClass::Variable]);

        let tree = self.browse_tree(node_id, config).await?;
        Ok(Self::flatten_tree(&tree))
    }

    /// Flattens a browse tree into a list.
    fn flatten_tree(node: &BrowseNode) -> Vec<BrowseNode> {
        let mut result = vec![node.clone()];
        for child in &node.children {
            result.extend(Self::flatten_tree(child));
        }
        result.into_iter().map(|mut n| {
            n.children.clear();
            n
        }).collect()
    }
}

// =============================================================================
// BrowseCache
// =============================================================================

/// Cache for browse results.
///
/// Improves performance for repeated browse operations on the same nodes.
#[derive(Debug)]
pub struct BrowseCache {
    /// Cached browse results.
    cache: RwLock<HashMap<String, CacheEntry>>,

    /// Maximum cache size.
    max_entries: usize,

    /// Cache TTL in seconds.
    ttl_seconds: u64,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    nodes: Vec<BrowseNode>,
    timestamp: std::time::Instant,
}

impl BrowseCache {
    /// Creates a new cache with default settings.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_entries: 1000,
            ttl_seconds: 300, // 5 minutes
        }
    }

    /// Creates a cache with custom settings.
    pub fn with_config(max_entries: usize, ttl_seconds: u64) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_entries,
            ttl_seconds,
        }
    }

    /// Gets cached results for a node.
    pub async fn get(&self, node_id: &NodeId, options: &BrowseOptions) -> Option<Vec<BrowseNode>> {
        let key = Self::cache_key(node_id, options);
        let cache = self.cache.read().await;

        if let Some(entry) = cache.get(&key) {
            if entry.timestamp.elapsed().as_secs() < self.ttl_seconds {
                return Some(entry.nodes.clone());
            }
        }
        None
    }

    /// Stores results in the cache.
    pub async fn put(&self, node_id: &NodeId, options: &BrowseOptions, nodes: Vec<BrowseNode>) {
        let key = Self::cache_key(node_id, options);
        let mut cache = self.cache.write().await;

        // Evict old entries if cache is full
        if cache.len() >= self.max_entries {
            self.evict_oldest(&mut cache);
        }

        cache.insert(key, CacheEntry {
            nodes,
            timestamp: std::time::Instant::now(),
        });
    }

    /// Clears the cache.
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Invalidates cache for a specific node.
    pub async fn invalidate(&self, node_id: &NodeId) {
        let prefix = node_id.to_string();
        let mut cache = self.cache.write().await;
        cache.retain(|k, _| !k.starts_with(&prefix));
    }

    fn cache_key(node_id: &NodeId, options: &BrowseOptions) -> String {
        format!("{}:{}:{}", node_id, options.direction as u8, options.node_class_mask())
    }

    fn evict_oldest(&self, cache: &mut HashMap<String, CacheEntry>) {
        // Simple eviction: remove oldest 10%
        let to_remove = cache.len() / 10;
        let mut entries: Vec<(String, std::time::Instant)> = cache
            .iter()
            .map(|(k, e)| (k.clone(), e.timestamp))
            .collect();
        entries.sort_by_key(|(_, t)| *t);

        for (key, _) in entries.into_iter().take(to_remove) {
            cache.remove(&key);
        }
    }
}

impl Default for BrowseCache {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// BrowseStatistics
// =============================================================================

/// Statistics for browse operations.
#[derive(Debug, Default)]
pub struct BrowseStatistics {
    /// Total browse operations performed.
    pub browse_count: std::sync::atomic::AtomicU64,

    /// Total nodes discovered.
    pub nodes_discovered: std::sync::atomic::AtomicU64,

    /// Cache hits.
    pub cache_hits: std::sync::atomic::AtomicU64,

    /// Cache misses.
    pub cache_misses: std::sync::atomic::AtomicU64,

    /// Browse errors.
    pub errors: std::sync::atomic::AtomicU64,
}

impl BrowseStatistics {
    /// Creates new statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a browse operation.
    pub fn record_browse(&self, node_count: usize) {
        use std::sync::atomic::Ordering;
        self.browse_count.fetch_add(1, Ordering::Relaxed);
        self.nodes_discovered.fetch_add(node_count as u64, Ordering::Relaxed);
    }

    /// Records a cache hit.
    pub fn record_cache_hit(&self) {
        use std::sync::atomic::Ordering;
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a cache miss.
    pub fn record_cache_miss(&self) {
        use std::sync::atomic::Ordering;
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an error.
    pub fn record_error(&self) {
        use std::sync::atomic::Ordering;
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the cache hit rate.
    pub fn cache_hit_rate(&self) -> f64 {
        use std::sync::atomic::Ordering;
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Resets all statistics.
    pub fn reset(&self) {
        use std::sync::atomic::Ordering;
        self.browse_count.store(0, Ordering::Relaxed);
        self.nodes_discovered.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
    }
}

// =============================================================================
// NodeBrowserImpl
// =============================================================================

/// Default implementation of the NodeBrowser trait.
///
/// Uses the OpcUaTransport for actual browse operations and provides
/// caching and statistics tracking.
pub struct NodeBrowserImpl<T: crate::client::OpcUaTransport> {
    /// Transport layer for OPC UA operations.
    transport: Arc<tokio::sync::Mutex<T>>,

    /// Optional browse cache.
    cache: Option<Arc<BrowseCache>>,

    /// Browse statistics.
    stats: Arc<BrowseStatistics>,
}

impl<T: crate::client::OpcUaTransport> NodeBrowserImpl<T> {
    /// Creates a new browser without caching.
    pub fn new(transport: Arc<tokio::sync::Mutex<T>>) -> Self {
        Self {
            transport,
            cache: None,
            stats: Arc::new(BrowseStatistics::new()),
        }
    }

    /// Creates a new browser with caching enabled.
    pub fn with_cache(transport: Arc<tokio::sync::Mutex<T>>, cache: Arc<BrowseCache>) -> Self {
        Self {
            transport,
            cache: Some(cache),
            stats: Arc::new(BrowseStatistics::new()),
        }
    }

    /// Returns a reference to the statistics.
    pub fn stats(&self) -> &BrowseStatistics {
        &self.stats
    }

    /// Performs the actual browse operation via transport.
    async fn do_browse(
        &self,
        node_id: &NodeId,
        options: &BrowseOptions,
    ) -> OpcUaResult<Vec<BrowseNode>> {
        let transport = self.transport.lock().await;

        let results = transport
            .browse_filtered(node_id, options.direction.value(), options.node_class_mask())
            .await?;

        let browse_nodes: Vec<BrowseNode> = results
            .into_iter()
            .filter(|r| !options.is_excluded(&r.node_id))
            .map(|r| {
                BrowseNode::new(
                    r.node_id,
                    QualifiedName::from(r.browse_name.as_str()),
                    r.display_name,
                    NodeClass::from_value(r.node_class).unwrap_or(NodeClass::Object),
                )
                .with_reference_type(r.reference_type.unwrap_or_default())
                .with_type_definition(r.type_definition.unwrap_or_default())
            })
            .collect();

        self.stats.record_browse(browse_nodes.len());

        Ok(browse_nodes)
    }

    /// Browses with optional caching.
    async fn browse_with_cache(
        &self,
        node_id: &NodeId,
        options: &BrowseOptions,
    ) -> OpcUaResult<Vec<BrowseNode>> {
        // Check cache first
        if let Some(ref cache) = self.cache {
            if let Some(cached) = cache.get(node_id, options).await {
                self.stats.record_cache_hit();
                return Ok(cached);
            }
            self.stats.record_cache_miss();
        }

        // Perform browse
        let results = self.do_browse(node_id, options).await?;

        // Store in cache
        if let Some(ref cache) = self.cache {
            cache.put(node_id, options, results.clone()).await;
        }

        Ok(results)
    }

    /// BFS traversal for tree browsing.
    async fn browse_tree_bfs(
        &self,
        root_id: &NodeId,
        root_node: &BrowseNode,
        config: &BrowseTreeConfig,
    ) -> OpcUaResult<HashMap<String, BrowseNode>> {
        let mut queue: VecDeque<(NodeId, Vec<String>, usize)> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut results: HashMap<String, BrowseNode> = HashMap::new();

        let root_key = root_id.to_string();
        visited.insert(root_key.clone());
        results.insert(root_key, root_node.clone());

        queue.push_back((root_id.clone(), vec![root_node.display_name.clone()], 0));

        while let Some((node_id, path, depth)) = queue.pop_front() {
            // Check limits
            if config.max_depth > 0 && depth >= config.max_depth {
                continue;
            }
            if results.len() >= config.max_nodes {
                break;
            }

            // Browse children
            let options = config.to_browse_options();
            let children = match self.browse_with_cache(&node_id, &options).await {
                Ok(c) => c,
                Err(_) => continue, // Skip nodes that fail to browse
            };

            for mut child in children {
                let child_key = child.node_id.to_string();

                if visited.contains(&child_key) {
                    continue;
                }
                visited.insert(child_key.clone());

                // Set path and depth
                let mut child_path = path.clone();
                child_path.push(child.display_name.clone());
                child.path = child_path.clone();
                child.depth = depth + 1;

                // Store result
                results.insert(child_key, child.clone());

                // Queue for further browsing if object
                if child.is_browsable() {
                    queue.push_back((child.node_id.clone(), child_path, depth + 1));
                }
            }
        }

        Ok(results)
    }
}

#[async_trait]
impl<T: crate::client::OpcUaTransport + 'static> NodeBrowser for NodeBrowserImpl<T> {
    async fn browse_children(
        &self,
        node_id: &NodeId,
        options: BrowseOptions,
    ) -> OpcUaResult<Vec<BrowseNode>> {
        self.browse_with_cache(node_id, &options).await
    }

    async fn browse_tree(
        &self,
        root_id: &NodeId,
        config: BrowseTreeConfig,
    ) -> OpcUaResult<BrowseNode> {
        // Get root node info
        let root_node = self.get_node_info(root_id).await?;

        // BFS traversal
        let mut results = self.browse_tree_bfs(root_id, &root_node, &config).await?;

        // Build tree structure
        let root_key = root_id.to_string();
        let mut result = results.remove(&root_key).unwrap_or(root_node);
        Self::build_tree_structure(&mut result, &mut results);

        Ok(result)
    }

    async fn find_by_path(&self, path: &BrowsePath) -> OpcUaResult<Option<BrowseNode>> {
        let mut current_node_id = path.start_node.clone();

        for segment in &path.segments {
            let options = BrowseOptions::default();
            let children = self.browse_with_cache(&current_node_id, &options).await?;

            let found = children.into_iter().find(|child| {
                segment.matches(&child.browse_name)
            });

            match found {
                Some(node) => current_node_id = node.node_id,
                None => return Ok(None),
            }
        }

        // Get detailed info for the found node
        let node_info = self.get_node_info(&current_node_id).await?;
        Ok(Some(node_info))
    }

    async fn get_node_info(&self, node_id: &NodeId) -> OpcUaResult<BrowseNode> {
        // Browse the node's parent to get its reference info
        // For now, return basic info (could be extended to read attributes)
        let transport = self.transport.lock().await;

        // Try to read display name
        let display_name = match transport.read_attribute(node_id, 4).await {
            Ok(result) if result.is_good() => {
                result.value.map(|v| v.to_string()).unwrap_or_else(|| node_id.to_string())
            }
            _ => node_id.to_string(),
        };

        // Try to read node class
        let node_class = match transport.read_attribute(node_id, 2).await {
            Ok(result) if result.is_good() => {
                result.value
                    .and_then(|v| v.as_i64())
                    .and_then(|v| NodeClass::from_value(v as u32))
                    .unwrap_or(NodeClass::Object)
            }
            _ => NodeClass::Object,
        };

        Ok(BrowseNode::new(
            node_id.clone(),
            QualifiedName::standard(&display_name),
            display_name,
            node_class,
        ))
    }
}

impl<T: crate::client::OpcUaTransport> NodeBrowserImpl<T> {
    /// Builds tree structure from flat results.
    fn build_tree_structure(parent: &mut BrowseNode, results: &mut HashMap<String, BrowseNode>) {
        // Find children by path
        let parent_path = parent.full_path();
        let depth = parent.depth;

        let child_keys: Vec<String> = results
            .iter()
            .filter(|(_, node)| {
                node.depth == depth + 1 && node.path.join("/") == parent_path
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in child_keys {
            if let Some(mut child) = results.remove(&key) {
                Self::build_tree_structure(&mut child, results);
                parent.add_child(child);
            }
        }
    }
}

impl<T: crate::client::OpcUaTransport> fmt::Debug for NodeBrowserImpl<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeBrowserImpl")
            .field("has_cache", &self.cache.is_some())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browse_options_default() {
        let options = BrowseOptions::default();
        assert_eq!(options.direction, BrowseDirection::Forward);
        assert!(options.node_class_filter.is_empty());
        assert!(options.include_subtypes);
    }

    #[test]
    fn test_browse_options_node_class_mask() {
        let options = BrowseOptions::default()
            .with_node_class_filter(vec![NodeClass::Object, NodeClass::Variable]);

        let mask = options.node_class_mask();
        assert_eq!(mask, NodeClass::Object.value() | NodeClass::Variable.value());
    }

    #[test]
    fn test_browse_options_matches_node_class() {
        let options = BrowseOptions::variables_only();

        assert!(options.matches_node_class(NodeClass::Variable));
        assert!(!options.matches_node_class(NodeClass::Object));
    }

    #[test]
    fn test_qualified_name_parsing() {
        let qn = QualifiedName::from("2:Temperature");
        assert_eq!(qn.namespace_index, 2);
        assert_eq!(qn.name, "Temperature");

        let qn = QualifiedName::from("Temperature");
        assert_eq!(qn.namespace_index, 0);
        assert_eq!(qn.name, "Temperature");
    }

    #[test]
    fn test_browse_path_from_string() {
        let path = BrowsePath::from_string("Objects/Server/Status").unwrap();
        assert_eq!(path.start_node, NodeId::OBJECTS_FOLDER);
        assert_eq!(path.segments.len(), 2);
        assert_eq!(path.segments[0].target_name.name, "Server");
        assert_eq!(path.segments[1].target_name.name, "Status");
    }

    #[test]
    fn test_browse_path_from_string_with_prefix() {
        let path = BrowsePath::from_string("Types/ObjectTypes/BaseObjectType").unwrap();
        assert_eq!(path.start_node, NodeId::TYPES_FOLDER);
        assert_eq!(path.segments.len(), 2);
    }

    #[test]
    fn test_browse_node_full_path() {
        let mut node = BrowseNode::new(
            NodeId::numeric(2, 1001),
            QualifiedName::new(2, "Status"),
            "Status".to_string(),
            NodeClass::Variable,
        );
        node.path = vec!["Objects".to_string(), "Server".to_string()];

        assert_eq!(node.full_path(), "Objects/Server/Status");
    }

    #[test]
    fn test_browse_node_has_value() {
        let variable = BrowseNode::new(
            NodeId::numeric(0, 1),
            QualifiedName::standard("Test"),
            "Test".to_string(),
            NodeClass::Variable,
        );
        assert!(variable.has_value());

        let object = BrowseNode::new(
            NodeId::numeric(0, 1),
            QualifiedName::standard("Test"),
            "Test".to_string(),
            NodeClass::Object,
        );
        assert!(!object.has_value());
    }

    #[test]
    fn test_browse_tree_config() {
        let config = BrowseTreeConfig::shallow();
        assert_eq!(config.max_depth, 1);

        let config = BrowseTreeConfig::deep();
        assert_eq!(config.max_depth, 10);
        assert!(config.read_attributes);
    }

    #[test]
    fn test_browse_statistics() {
        let stats = BrowseStatistics::new();

        stats.record_browse(10);
        stats.record_cache_hit();
        stats.record_cache_miss();
        stats.record_cache_hit();

        use std::sync::atomic::Ordering;
        assert_eq!(stats.browse_count.load(Ordering::Relaxed), 1);
        assert_eq!(stats.nodes_discovered.load(Ordering::Relaxed), 10);
        assert!((stats.cache_hit_rate() - 0.666).abs() < 0.01);
    }
}
