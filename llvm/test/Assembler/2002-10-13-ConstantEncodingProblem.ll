%Domain = type { sbyte*, %List_o_links*, %D_tree_leaf*, %Domain* }
%List_o_links = type { int, int, int, %List_o_links* }
%D_tree_leaf = type { %Domain*, int, %D_tree_leaf* }

%D = global %Domain { sbyte* null, %List_o_links* null, %D_tree_leaf* null, %Domain* null }

implementation

