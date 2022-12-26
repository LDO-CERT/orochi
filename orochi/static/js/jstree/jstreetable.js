/*
 * http://github.com/adamjimenez/jstree-table
 *
 * This plugin handles adding columns to a tree to display additional data
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Works only with jstree version >= 3.0.0
 *
 * $Revision:  3.4.2 $
 */

/*jslint nomen:true */
/*jshint unused:vars */
/*global navigator, document, jQuery, define, localStorage */

(function (factory) {
	if (typeof define === 'function' && define.amd) {
		// AMD. Register as an anonymous module.
		define(['jquery', 'jstree'], factory);
	} else {
		// Browser globals
		factory(jQuery);
	}
}(function ($) {
	var renderATitle, getIndent, copyData, htmlstripre, findLastClosedNode, BLANKRE = /^\s*$/g,
		IDREGEX = /[\\:&!^|()\[\]<>@*'+~#";,= \/${}%]/g, escapeId = function (id) {
			return (id||"").replace(IDREGEX,'\\$&');
		}, NODE_DATA_ATTR = "data-jstreetable", COL_DATA_ATTR = "data-jstreetable-column",
	SPECIAL_TITLE = "_DATA_", LEVELINDENT = 24, styled = false, TABLECELLID_PREFIX = "jstable_",TABLECELLID_POSTFIX = "_col",
		MINCOLWIDTH = 10,
		findDataCell = function (from,id) {
			return from.find("div["+NODE_DATA_ATTR+'="'+ escapeId(id) +'"]');
		},
		isClickedSep = false, toResize = null, oldMouseX = 0, newMouseX = 0;

	/*jslint regexp:true */
	htmlstripre = /<\/?[^>]+>/gi;
	/*jslint regexp:false */

	getIndent = function(node,tree) {
		var div, i, li, width;

		// did we already save it for this tree?
		tree._tableSettings = tree._tableSettings || {};
		if (tree._tableSettings.indent > 0) {
			width = tree._tableSettings.indent;
		} else {
			// create a new div on the DOM but not visible on the page
			div = $("<div></div>");
			i = node.prev("i");
			li = i.parent();
			// add to that div all of the classes on the tree root
			div.addClass(tree.get_node("#",true).attr("class"));

			// move the li to the temporary div root
			li.appendTo(div);

			// attach to the body quickly
			div.appendTo($("body"));

			// get the width
			width = i.width() || LEVELINDENT;

			// detach the li from the new div and destroy the new div
			li.detach();
			div.remove();

			// save it for the future
			tree._tableSettings.indent = width;
		}


		return(width);

	};

	copyData = function (fromtree,from,totree,to,recurse) {
		var i, j;
	  to.data = $.extend(true, {}, from.data);
		if (from && from.children_d && recurse) {
			for(i = 0, j = from.children_d.length; i < j; i++) {
			   copyData(fromtree,fromtree.get_node(from.children_d[i]),totree,totree.get_node(to.children_d[i]),recurse);
			}
		}
	};

	findLastClosedNode = function (tree,id) {
		// first get our node
		var ret, node = tree.get_node(id), children = node.children;
		// is it closed?
		if (!children || children.length <= 0 || !node.state.opened) {
			ret = id;
		} else {
			ret = findLastClosedNode(tree,children[children.length-1]);
		}
		return(ret);
	};

	renderAWidth = function(node,tree) {
		var depth, width,
		fullWidth = parseInt(tree.settings.table.columns[0].width,10) + parseInt(tree._tableSettings.treeWidthDiff,10);
		// need to use a selector in jquery 1.4.4+
		depth = tree.get_node(node).parents.length;
		width = fullWidth - depth*getIndent(node,tree);
		// the following line is no longer needed, since we are doing this inside a <td>
		//a.css({"vertical-align": "top", "overflow":"hidden"});
		return(fullWidth);
	};
	renderATitle = function(node,t,tree) {
		var a = node.get(0).tagName.toLowerCase() === "a" ? node : node.children("a"), title, col = tree.settings.table.columns[0];
		// get the title
		title = "";
		if (col.title) {
			if (col.title === SPECIAL_TITLE) {
				title = tree.get_text(t);
			} else if (t.attr(col.title)) {
				title = t.attr(col.title);
			}
		}
		// strip out HTML
		title = title.replace(htmlstripre, '');
		if (title) {
			a.attr("title",title);
		}
	};

	$.jstree.defaults.table = {
		width: 'auto'
	};

	$.jstree.plugins.table = function(options,parent) {
		var _this = this;

		this._initialize = function () {
			if (!this._initialized) {
				var s = this.settings.table || {}, styles,	container = this.element, i,
				gs = this._tableSettings = {
					columns : s.columns || [],
					treeClass : "jstree-table-col-0",
					context: s.contextmenu || false,
					columnWidth : s.columnWidth,
					defaultConf : {"*display":"inline","*+display":"inline"},
					isThemeroller : !!this._data.themeroller,
					treeWidthDiff : 0,
					resizable : s.resizable,
					draggable : s.draggable,
					stateful: s.stateful,
					indent: 0,
					sortFn: [],
					sortOrder: 'text',
					sortAsc: true,
					fixedHeader: s.fixedHeader !== false,
					headerContextMenu: s.headerContextMenu !== false,
					checkIcon: 'fa fa-check',
					arrowDownIcon: 'fa fa-chevron-down',
					arrowUpIcon: 'fa fa-chevron-up',
					width: s.width,
					height: s.height
				}, cols = gs.columns, treecol = 0;
				// find which column our tree shuld go in
				for (i=0;i<s.columns.length;i++) {
					//Save sort function
					if (i!==0 && s.columns[i].sort) {
						gs.sortFn[s.columns[i].value] = s.columns[i].sort;
					}
					if (s.columns[i].tree) {
						// save which column it was
						treecol = i;
						// do not check any others
						break;
					}
				}
				// set a unique ID for this table
				this.uniq = Math.ceil(Math.random()*1000);
				this.rootid = container.attr("id");

				var msie = /msie/.test(navigator.userAgent.toLowerCase());
				if (msie) {
					var version = parseFloat(navigator.appVersion.split("MSIE")[1]);
					if (version < 8) {
						gs.defaultConf.display = "inline";
						gs.defaultConf.zoom = "1";
					}
				}

				// set up the classes we need
				if (!styled) {
					styled = true;
					styles = [
						'.jstree-table-cell {vertical-align: top; overflow:hidden;margin-left:0;width: 100%;padding-left:7px;white-space: nowrap; cursor: default; text-overflow: ellipsis;}',
						'.jstree-table-cell span {margin-right:0px;margin-right:0px;*display:inline;*+display:inline;white-space: nowrap;}',
						'.jstree-table-separator {position:absolute; top:0; right:0; height:24px; margin-left: -2px; border-width: 0 2px 0 0; *display:inline; *+display:inline; margin-right:0px;width:0px;}',
						'.jstree-table-header-cell {display: table-cell; overflow: hidden; white-space: nowrap;padding: 4px 3px 2px 5px; cursor: default;}',
						'.jstree-table-header-themeroller {border: 0; padding: 1px 3px;}',
						'.jstree-table-header-regular {position:relative; background-color: #CBF3FD; z-index: 1;}',
						'.jstree-table-resizable-separator {cursor: col-resize; width: 10px;}',
						'.jstree-table-separator-regular {border-color: #d0d0d0; border-style: solid;}',
						'.jstree-table-cell-themeroller {border: none !important; background: transparent !important;}',
						'.jstree-table-wrapper {table-layout: fixed; width: 100%; overflow: auto; position: relative;}',
						'.jstree-table-headerwrapper {display: table-row; position: sticky; top: 0; z-index: 1}',
						'.jstree-table-midwrapper {display: table-row;}',
						'.jstree-table-width-auto {width:auto;display:block;}',
						'.jstree-table-column {display: table-cell; vertical-align: top; overflow: hidden;}',
						'.jstree-table-col-0 {width: calc(100% - 18px); overflow: hidden; text-overflow: ellipsis;}',
						'.jstree-table-sort-icon {font-size: 8px; position: absolute; top:0; left: calc(50% - 4px);}',
						'.jstree-table-midwrapper a.jstree-clicked, .jstree-table-midwrapper a.jstree-hovered{background: transparent; border-color: transparent;}',
						'.jstree-table-midwrapper a.jstree-clicked:before, .jstree-table-midwrapper a.jstree-hovered:before {position: absolute; left: 0; content:""; height: inherit; z-index: -1;}',
						'.jstree-table-midwrapper a.jstree-hovered:before {background: #e7f4f9;}',
						'.jstree-table-midwrapper a.jstree-clicked:before {background: #beebff;}',
						'.vakata-context {z-index:2;}'
					];

					$('<style type="text/css">'+styles.join("\n")+'</style>').appendTo("head");
				}
				this.tableWrapper = $("<div></div>").addClass("jstree-table-wrapper").insertAfter(container);
				this.headerWrapper = $("<div></div>").addClass("jstree-table-headerwrapper").appendTo(this.tableWrapper);
				this.midWrapper = $("<div></div>").addClass("jstree-table-midwrapper").appendTo(this.tableWrapper);
				// set the wrapper width
				if (s.width) {
					this.tableWrapper.width(s.width);
				}
				if (s.height) {
					this.tableWrapper.height(s.height);
				}
				// create the data columns
				for (i=0;i<cols.length;i++) {
					// create the column
					$("<div></div>").addClass("jstree-default jstree-table-column jstree-table-column-"+i+" jstree-table-column-root-"+this.rootid).appendTo(this.midWrapper);
				}
				this.midWrapper.children("div:eq("+treecol+")").append(container);
				container.addClass("jstree-table-cell");

				//move header with scroll
				/*
				if (gs.fixedHeader) {
					this.tableWrapper.scroll(function() {
						$(this).find('.jstree-table-header').css('top', $(this).scrollTop());
					});
				}
				*/

				// copy original sort function
				var defaultSort = $.proxy(this.settings.sort, this);

				// override sort function
				this.settings.sort = function (a, b) {
					var bigger;

					if (gs.sortOrder==='text') {
						bigger = defaultSort(a, b);
					} else {
						var nodeA = this.get_node(a);
						var nodeB = this.get_node(b);
						var valueA = nodeA.data[gs.sortOrder];
						var valueB = nodeB.data[gs.sortOrder];
						if(valueA && valueB){
							if(gs.sortFn[gs.sortOrder]){
								bigger = gs.sortFn[gs.sortOrder](valueA, valueB, nodeA, nodeB);
							}else{
								// Default sorting
								bigger = (valueA > valueB ? 1 : -1);
							}
						}else{
							// undefined is second
							if(valueA){
								bigger = 1;
							}else if(valueB){
								bigger = -1;
							}else{
								// Compare two nodes without values
								bigger = defaultSort(a, b);
							}
						}
					}

					if (gs.sortAsc===false){
						bigger = -bigger;

					}

					return bigger;
				};

				// sortable columns when jQuery UI is available
				if (gs.draggable) {
					if (!$.ui || !$.ui.sortable) {
						console.warn('[jstree-table] draggable option requires jQuery UI');
					} else {
						var from, to;
						this.headerWrapper.sortable({
							axis: "x",
							//handle: ".jstree-table-header-cell",
							cancel: ".jstree-table-separator",
							start: function (event, ui) {
								ui.item.parent().children().css('display', 'inline-block');
								from = ui.item.index();
							},
							stop: function (event, ui) {
								ui.item.parent().children().css('display', 'table-cell');
								to = ui.item.index();

								if (to===from) return;

								gs.columns.splice(to, 0, gs.columns.splice(from, 1)[0]);

								var col = $('.jstree-table-midwrapper>div').eq(from);
								if (to>from) {
									col.insertAfter(col.parent().children("div").eq(to));
								} else if (to<from){
									col.insertBefore(col.parent().children("div").eq(to));
								}

							}
						});
						$( "#sortable" ).disableSelection();
					}
				}

				this._initialized = true;
			}
		};
		this.init = function (el,options) {
			parent.init.call(this,el,options);
			this._initialize();
		};
		this.bind = function () {
			parent.bind.call(this);
			this._initialize();
			this.element
			.on("move_node.jstree create_node.jstree clean_node.jstree change_node.jstree", $.proxy(function (e, data) {
				var target = this.get_node(data || "#",true);
				this._prepare_table(target);
			}, this))
			.on("delete_node.jstree",$.proxy(function (e,data) {
				if (data.node.id !== undefined) {
					var table = this.tableWrapper, removeNodes = [data.node.id], i;
					// add children to remove list
					if (data.node && data.node.children_d) {
						removeNodes = removeNodes.concat(data.node.children_d);
					}
					for (i=0;i<removeNodes.length;i++) {
						findDataCell(table,removeNodes[i]).remove();
					}
				}
			}, this))
			.on("close_node.jstree",$.proxy(function (e,data) {
				this._hide_table(data.node);
			}, this))
			.on("open_node.jstree",$.proxy(function (e,data) {
			}, this))
			.on("load_node.jstree",$.proxy(function (e,data) {
			}, this))
			.on("loaded.jstree", $.proxy(function (e) {
				this._prepare_headers();
				this.element.trigger("loaded_table.jstree");
				}, this))
			.on("ready.jstree",$.proxy(function (e,data) {
				var cls = this.element.attr("class") || "";

				// add container classes to the wrapper - EXCEPT those that are added by jstree, i.e. "jstree" and "jstree-*"
				q = cls.split(/\s+/).map(function(i) {
				  var match = i.match(/^jstree(-|$)/);
				  return (match ? "" : i);
				});
				this.tableWrapper.addClass(q.join(" "));

				var me = this;
				function resize() {
					// find the line-height of the first known node
					var anchorHeight = me.element.find(".jstree-leaf").outerHeight() || 24;

					// resize the hover/ focus highlight
					var tableWidth = $('.jstree-table-midwrapper').width();

					$('#jsTreeTableExtraCss').remove();
					$('<style type="text/css" id="jsTreeTableExtraCss">\
						div.jstree-table-cell-root-'+me.rootid+' {line-height: '+anchorHeight+'px; min-height: '+anchorHeight+'px;}\
						div.jstree-table-midwrapper a.jstree-clicked:before, .jstree-table-midwrapper a.jstree-hovered:before {width: ' + tableWidth + 'px;}\
					</style>').appendTo("head");
				}

				resize();

				// resize column headers
				this.autosize_all_columns();

				// resize rows on zoom
				$(window).on('resize', resize);

				// resize column expand
				this.element.on("resize_column.jstree-table", resize);
			},this))
			.on("move_node.jstree",$.proxy(function(e,data) {
				var node = data.new_instance.element;
				//renderAWidth(node,this);
				// check all the children, because we could drag a tree over
				node.find("li > a").each($.proxy(function(i,elm) {
					//renderAWidth($(elm),this);
				},this));
			},this))
			.on("select_node.jstree",$.proxy(function(node,selected,event){
				var id = selected.node.id;
				findDataCell(this.tableWrapper,id).addClass("jstree-clicked");
				this.get_node(selected.node.id,true).children("div.jstree-table-cell").addClass("jstree-clicked");
			},this))
			.on("deselect_node.jstree",$.proxy(function(node,selected,event){
				var id = selected.node.id;
				findDataCell(this.tableWrapper,id).removeClass("jstree-clicked");
			},this))
			.on("deselect_all.jstree",$.proxy(function(node,selected,event){
				// get all of the ids that were unselected
				var ids = selected.node || [], i;
				for (i=0;i<ids.length;i++) {
					findDataCell(this.tableWrapper,ids[i]).removeClass("jstree-clicked");
				}
			},this))
			.on("search.jstree", $.proxy(function (e, data) {
				// search sometimes filters, so we need to hide all of the appropriate table cells as well, and show only the matches
				var table = this.tableWrapper;
				if(this._data.search.som) {
					if(data.nodes.length) {
						// hide all of the table cells
						table.find('div.jstree-table-cell-regular').hide();
						// show only those that match
						data.nodes.add(data.nodes.parentsUntil(".jstree")).filter(".jstree-node").each(function (i,node) {
							var id = node.id;
							if (id) {
								findDataCell(table,id).show();
							}
						});
					}
				}
				return true;
			}, this))
			.on("clear_search.jstree", $.proxy(function (e, data) {
				// search has been cleared, so we need to show all rows
				this.tableWrapper.find('div.jstree-table-cell').show();
				return true;
			}, this))
			.on("copy_node.jstree", function (e, data) {
				var newtree = data.new_instance, oldtree = data.old_instance, obj = newtree.get_node(data.node,true);
				copyData(oldtree,data.original,newtree,data.node,true);
				newtree._prepare_table(obj);
				return true;
			});
			if (this._tableSettings.isThemeroller) {
				this.element
					.on("select_node.jstree",$.proxy(function(e,data) {
						data.rslt.obj.children("a").nextAll("div").addClass("ui-state-active");
					},this))
					.on("deselect_node.jstree deselect_all.jstree",$.proxy(function(e,data) {
						data.rslt.obj.children("a").nextAll("div").removeClass("ui-state-active");
					},this))
					.on("hover_node.jstree",$.proxy(function(e,data) {
						data.rslt.obj.children("a").nextAll("div").addClass("ui-state-hover");
					},this))
					.on("dehover_node.jstree",$.proxy(function(e,data) {
						data.rslt.obj.children("a").nextAll("div").removeClass("ui-state-hover");
					},this));
			}

			if (this._tableSettings.stateful) {
				this.element
					.on("resize_column.jstree-table",$.proxy(function(e,col,width) {
						localStorage['jstree-root-'+this.rootid+'-column-'+col] = width;
					},this));
			}
		};
		// tear down the tree entirely
		this.teardown = function() {
			var gw = this.tableWrapper, container = this.element, tableparent = gw.parent();
			container.detach();
			gw.remove();
			tableparent.append(container);
			parent.teardown.call(this);
		};
		// clean the table in case of redraw or refresh entire tree
		this._clean_table = function (target,id) {
			var table = this.tableWrapper;
			if (target) {
				findDataCell(table,id).remove();
			} else {
				// get all of the `div` children in all of the `td` in dataRow except for :first (that is the tree itself) and remove
				table.find("div.jstree-table-cell-regular").remove();
			}
		};
		// prepare the headers
		this._prepare_headers = function() {
			var header, i, col, _this = this, gs = this._tableSettings,cols = gs.columns || [], width, defaultWidth = gs.columnWidth, resizable = gs.resizable || false,
			cl, ccl, val, name, margin, last, tr = gs.isThemeroller, classAdd = (tr?"themeroller":"regular"), puller,
			hasHeaders = false, tableparent = this.tableparent, rootid = this.rootid,
			conf = gs.defaultConf,
			borPadWidth = 0, totalWidth = 0;
			// save the original parent so we can reparent on destroy
			this.parent = tableparent;


			// create the headers
			for (i=0;i<cols.length;i++) {
				//col = $("<col/>");
				//col.appendTo(colgroup);
				cl = cols[i].headerClass || "";
				ccl = cols[i].columnClass || "";
				val = cols[i].header || "";
				name = cols[i].value || "text";

				if (val) {hasHeaders = true;}
				if(gs.stateful && localStorage['jstree-root-'+rootid+'-column-'+i])
					width = localStorage['jstree-root-'+rootid+'-column-'+i];
				else
					width = cols[i].width || defaultWidth;

				col = this.headerWrapper;
				last = $("<div></div>").css(conf).addClass("jstree-table-div-"+this.uniq+"-"+i+" "+(tr?"ui-widget-header ":"")+" jstree-table-header jstree-table-header-cell jstree-table-header-"+classAdd+" "+cl+" "+ccl).html(val);
				last.addClass((tr?"ui-widget-header ":"")+"jstree-table-header jstree-table-header-"+classAdd);
				last.appendTo(col);

				if (name) {
					last.attr(COL_DATA_ATTR, name);
				}
				last.hover(function () {
					$(this).addClass("jstree-hovered jstree-table-header-hovered");
				}, function () {
					$(this).removeClass("jstree-hovered jstree-table-header-hovered");
				});
				totalWidth += last.outerWidth();
				puller = $("<div class='jstree-table-separator jstree-table-separator-"+classAdd+(tr ? " ui-widget-header" : "")+(resizable? " jstree-table-resizable-separator":"")+"'>&nbsp;</div>").appendTo(last);
			}

			last.addClass((tr?"ui-widget-header ":"")+"jstree-table-header jstree-table-header-last jstree-table-header-"+classAdd);
			// if there is no width given for the last column, do it via automatic
			if (cols[cols.length-1].width === undefined) {
				totalWidth -= width;
				col.css({width:"auto"});
				last.addClass("jstree-table-width-auto").next(".jstree-table-separator").remove();
			}
			if (hasHeaders) {
				// save the offset of the div from the body
				//gs.divOffset = header.parent().offset().left;
				gs.header = header;
			} else {
				$("div.jstree-table-header").hide();
			}

			if (!this.bound && resizable) {
				this.bound = true;
				$(document).mouseup(function () {
					var ref, cols, width, headers, currentTree, colNum;
					if (isClickedSep) {
						colNum = toResize.prevAll(".jstree-table-column").length;
						currentTree = toResize.closest(".jstree-table-wrapper").find(".jstree");
						ref = $.jstree.reference(currentTree);
						cols = ref.settings.table.columns;
						headers = toResize.parent().children("div.jstree-table-column");
						if (isNaN(colNum) || colNum < 0) { ref._tableSettings.treeWidthDiff = currentTree.find("ins:eq(0)").width() + currentTree.find("a:eq(0)").width() - ref._tableSettings.columns[0].width; }
						width = ref._tableSettings.columns[colNum].width = parseFloat(toResize.css("width"));
						isClickedSep = false;
						toResize = null;

						currentTree.trigger("resize_column.jstree-table", [colNum,width]);
					}
				}).mousemove(function (e) {
					if (isClickedSep) {
						newMouseX = e.pageX;
						var diff = newMouseX - oldMouseX,
						oldPrevHeaderInner,
						oldPrevColWidth, newPrevColWidth;

						if (diff !== 0) {
							oldPrevHeaderInner = toResize.width();
							oldPrevColWidth = parseFloat(toResize.css("width"));

							// handle a Chrome issue with columns set to auto
							// thanks to Brabus https://github.com/side-by-side
							if (!oldPrevColWidth) {
								oldPrevColWidth = toResize.innerWidth();
							}

							// make sure that diff cannot be beyond the left/right limits
							diff = diff < 0 ? Math.max(diff,-oldPrevHeaderInner) : diff;
							newPrevColWidth = oldPrevColWidth+diff;

							// only do this if we are not shrinking past 0 on left - and limit it to that amount
							if ((diff > 0 || oldPrevHeaderInner > 0) && newPrevColWidth > MINCOLWIDTH) {
								var index = toResize.parent().children().index(toResize);
								var col = $('.jstree-table-midwrapper>div').eq(index);

								toResize.width(newPrevColWidth+"px");
								toResize.css("min-width",newPrevColWidth+"px");
								toResize.css("max-width",newPrevColWidth+"px");

								col.width(newPrevColWidth+"px");
								col.css("min-width",newPrevColWidth+"px");
								col.css("max-width",newPrevColWidth+"px");

								oldMouseX = newMouseX;
							}
						}
					}
				});
				this.tableWrapper.on("selectstart", ".jstree-table-resizable-separator", function () {
					return false;
				})
				.on("mousedown", ".jstree-table-resizable-separator", function (e) {
					isClickedSep = true;
					oldMouseX = e.pageX;
					toResize = $(this).closest("div.jstree-table-header");
					// the max rightmost position we will allow is the right-most of the wrapper minus a buffer (10)
					return false;
				})
				.on("dblclick", ".jstree-table-resizable-separator", function (e) {
					var headerCol = $(this).closest("div.jstree-table-header");
					var index = headerCol.parent().children().index(headerCol);
					var col = $('.jstree-table-midwrapper>div').eq(index);
					_this.autosize_column(col);
				})
				.on("click", ".jstree-table-separator", function (e) {
					// don't sort after resize
					e.stopPropagation();
				});
			}

			this.tableWrapper.on("click", ".jstree-table-header-cell", function (e) {
				if (!_this.sort) { return; }

				// get column
				var name = $(this).attr(COL_DATA_ATTR);
				if (!name) { return; }

				// sort order
				var arrowClass;
				if (gs.sortOrder === name && gs.sortAsc === true) {
					gs.sortAsc = false;
					arrowClass = gs.arrowDownIcon;
				} else {
					gs.sortOrder = name;
					gs.sortAsc = true;
					arrowClass = gs.arrowUpIcon;
				}

				// add sort arrow
				$(this).closest('.jstree-table-wrapper').find(".jstree-table-sort-icon").remove();
				$("<span></span>").addClass("jstree-table-sort-icon").appendTo($(this)).addClass(arrowClass);

				// sort by column
				var rootNode = _this.get_node('#');
				_this.sort(rootNode, true);
				_this.redraw_node(rootNode, true);
			});

			// header context menu
			this.headerWrapper.on("contextmenu", ".jstree-table-header-cell", function(e) {
				if (!gs.headerContextMenu) { return; }
					e.preventDefault();

					var options = {
						"fit":{label:"Size column to fit","action": function (data) {
							var headerCol = $(e.target).closest("div.jstree-table-header");
							var index = headerCol.parent().children().index(headerCol);
							var col = $('.jstree-table-midwrapper>div').eq(index);

							_this.autosize_column(col);
						}},
						"fitAll":{"separator_after": true,label:"Size all columns to fit","action": function (data) {
							_this.autosize_all_columns();
						}}
					};

					// create menu item for every header cell
					var cell, icon, value, label;
					_this.midWrapper.find(".jstree-table-header-cell").each(function() {
						cell = $(this);
						icon = cell.is(":visible") ? gs.checkIcon : false;
						value = cell.attr(COL_DATA_ATTR);
						//get label without sorting arrows
						label = cell.clone().children('.jstree-table-sort-icon').remove().end().text().trim();

						options[value] = {icon:icon, column:value, label:label, _disabled: (value === 'text'), "action": function (data) {
							var col = _this.midWrapper.find(".jstree-table-header-cell["+COL_DATA_ATTR+"='"+data.item.column+"']").parent();
							col.toggle();
						}};
					});

					$.vakata.context.show(this,{ 'x' : e.pageX, 'y' : e.pageY },options);
			});
		};


		/*
		 * Override redraw_node to correctly insert the table
		 */
		this.redraw_node = function(obj, deep, is_callback, force_render) {
			// first allow the parent to redraw the node
			obj = parent.redraw_node.call(this, obj, deep, is_callback, force_render);
			// next prepare the table
			if(obj) {
				this._prepare_table(obj);
			}
			return obj;
		};
		this.refresh = function () {
			this._clean_table();
			return parent.refresh.apply(this,arguments);
		};
		/*
		 * Override set_id to update cell attributes
		 */
		this.set_id = function (obj, id) {
			var old;
			if(obj) {
				old = obj.id;
			}
			var result = parent.set_id.apply(this,arguments);
			if(result) {
				if (old !== undefined) {
					var table = this.tableWrapper, oldNodes = [old], i;
					// get children
					if (obj && obj.children_d) {
						oldNodes = oldNodes.concat(obj.children_d);
					}
					// update id in children
					for (i=0;i<oldNodes.length;i++) {
						findDataCell(table,oldNodes[i])
						.attr(NODE_DATA_ATTR, obj.id)
						.attr('id', TABLECELLID_PREFIX+obj.id+TABLECELLID_POSTFIX+(i+1))
						.removeClass(TABLECELLID_PREFIX+old+TABLECELLID_POSTFIX)
						.addClass(TABLECELLID_PREFIX+obj.id+TABLECELLID_POSTFIX);
					}
				}
			}
			return result;
		};
		this._hide_table = function (node) {
			var children = node && node.children_d ? node.children_d : [], i;
			// go through each column, remove all children with the correct ID name
			for (i=0;i<children.length;i++) {
				findDataCell(this.tableWrapper,children[i]).remove();
			}
		};
		this.holdingCells = {};
		this.getHoldingCells = function (obj,col,hc) {
			var ret = $(), children = obj.children||[], child, i;
			// run through each child, render it, and then render its children recursively
			for (i=0;i<children.length;i++) {
				child = TABLECELLID_PREFIX+escapeId(children[i])+TABLECELLID_POSTFIX+col;
				if (hc[child] && obj.state.opened) {
					ret = ret.add(hc[child]).add(this.getHoldingCells(this.get_node(children[i]),col,hc));
					//delete hc[child];
				}
			}
			return(ret);
		};
		/**
		 * put a table cell in edit mode (input field to edit the data)
		 * @name edit(obj, col)
		 * @param  {mixed} obj
		 * @param  {obj} col definition
		 * @param  {element} cell element, either span or wrapping div
		 */
		this._edit = function (obj, col, element) {
			if(!obj) { return false; }
			if (element) {
				element = $(element);
				if (element.prop("tagName").toLowerCase() === "div") {
					element = element.children("span:first");
				}
			} else {
				// need to find the element - later
				return false;
			}
			var rtl = this._data.core.rtl,
				w  = this.element.width(),
				t = obj.data[col.value],
				h1 = $("<"+"div />", { css : { "position" : "absolute", "top" : "-200px", "left" : (rtl ? "0px" : "-1000px"), "visibility" : "hidden" } }).appendTo("body"),
				h2 = $("<"+"input />", {
						"value" : t,
						"class" : "jstree-rename-input",
						"css" : {
							"padding" : "0",
							"border" : "1px solid silver",
							"box-sizing" : "border-box",
							"display" : "inline-block",
							"height" : (this._data.core.li_height) + "px",
							"lineHeight" : (this._data.core.li_height) + "px",
							"width" : "150px" // will be set a bit further down
						},
						"blur" : $.proxy(function () {
							var v = h2.val();
							// save the value if changed
							if(v === "" || v === t) {
								v = t;
							} else {
								obj.data[col.value] = v;
								this.element.trigger('update_cell.jstree-table',{node:obj, col:col.value, value:v, old:t});
								this._prepare_table(this.get_node(obj,true));
							}
							h2.remove();
							element.show();
						}, this),
						"keydown" : function (event) {
							var key = event.which;
							if(key === 27) {
								this.value = t;
							}
							if(key === 27 || key === 13 || key === 37 || key === 38 || key === 39 || key === 40 || key === 32) {
								event.stopImmediatePropagation();
							}
							if(key === 27 || key === 13) {
								event.preventDefault();
								this.blur();
							}
						},
						"click" : function (e) { e.stopImmediatePropagation(); },
						"mousedown" : function (e) { e.stopImmediatePropagation(); },
						"keyup" : function (event) {
							h2.width(Math.min(h1.text("pW" + this.value).width(),w));
						},
						"keypress" : function(event) {
							if(event.which === 13) { return false; }
						}
					}),
				fn = {
						fontFamily		: element.css('fontFamily')		|| '',
						fontSize		: element.css('fontSize')			|| '',
						fontWeight		: element.css('fontWeight')		|| '',
						fontStyle		: element.css('fontStyle')		|| '',
						fontStretch		: element.css('fontStretch')		|| '',
						fontVariant		: element.css('fontVariant')		|| '',
						letterSpacing	: element.css('letterSpacing')	|| '',
						wordSpacing		: element.css('wordSpacing')		|| ''
				};
			element.hide();
			element.parent().append(h2);
			h2.css(fn).width(Math.min(h1.text("pW" + h2[0].value).width(),w))[0].select();
		};

		this.autosize_column = function (col) {
			// don't resize hidden columns
			if (col.is(":hidden")) { return; }

			var oldPrevColWidth = parseFloat(col.css("width")), newWidth = 0, diff,
			colNum = col.prevAll(".jstree-table-column").length,
			oldPrevHeaderInner = col.width(), newPrevColWidth;

			//find largest width
			col.find(".jstree-table-cell").each(function() {
				var item = $(this), width;
				item.css("position", "absolute");
				item.css("width", "auto");
				width = item.outerWidth();
				item.css("position", "static");

				if (width>newWidth) {
					newWidth = width;
				}
			});

			diff = newWidth-oldPrevColWidth;

			// make sure that diff cannot be beyond the left limits
			diff = diff < 0 ? Math.max(diff,-oldPrevHeaderInner) : diff;
			newPrevColWidth = (oldPrevColWidth+diff)+"px";

			col.width(newPrevColWidth);
			col.css("min-width",newPrevColWidth);
			col.css("max-width",newPrevColWidth);

			var index = col.parent().children().index(col);
			var headerCol = $('.jstree-table-headerwrapper>div').eq(index);
			headerCol.width(newPrevColWidth);
			headerCol.css("min-width",newPrevColWidth);
			headerCol.css("max-width",newPrevColWidth);

			$(this).closest(".jstree-table-wrapper").find(".jstree").trigger("resize_column.jstree-table",[colNum,newPrevColWidth]);
		};

		this.autosize_all_columns = function () {
			this.tableWrapper.find(".jstree-table-column").each(function() {
				_this.autosize_column($(this));
			});
		};

		this._prepare_table = function (obj) {
			var gs = this._tableSettings, c = gs.treeClass, _this = this, t, cols = gs.columns || [], width, tr = gs.isThemeroller,
			tree = this.element, rootid = this.rootid,
			classAdd = (tr?"themeroller":"regular"), img, objData = this.get_node(obj),
			defaultWidth = gs.columnWidth, conf = gs.defaultConf, cellClickHandler = function (tree,node,val,col,t) {
				return function(e) {
					node.children(".jstree-anchor").trigger("click",e);
				};
			}, cellDblClickHandler = function (tree,node,val,col,t) {
				return function(e) {
					node.children(".jstree-anchor").trigger("dblclick",e);
				};
			}, cellRightClickHandler = function (tree,node,val,col,t) {
				return function (e) {
					if (gs.context) {
						e.preventDefault();
						$.vakata.context.show(this,{ 'x' : e.pageX, 'y' : e.pageY },{
							"edit":{label:"Edit","action": function (data) {
								var obj = t.get_node(node);
								_this._edit(obj,col,e.target);
							}}
						});
					}
				};
			},
			hoverInHandler = function (node, jsTreeInstance) {
				return function() { jsTreeInstance.hover_node(node); };
			},
			hoverOutHandler = function (node, jsTreeInstance) {
				return function() { jsTreeInstance.dehover_node(node); };
			},
			i, val, cl, wcl, ccl, a, last, valClass, wideValClass, span, paddingleft, title, tableCellName, tableCellParentId, tableCellParent,
			tableCellPrev, tableCellPrevId, tableCellNext, tableCellNextId, tableCellChild, tableCellChildId,
			col, content, tmpWidth, mw = this.midWrapper, dataCell, lid = objData.id,
			peers = this.get_node(objData.parent).children,
			// find my position in the list of peers. "peers" is the list of everyone at my level under my parent, in order
			pos = $.inArray(lid,peers),
			hc = this.holdingCells, rendered = false, closed;
			// get our column definition
			t = $(obj);

			// find the a children
			a = t.children("a");

			if (a.length === 1) {
				closed = !objData.state.opened;
				tableCellName = TABLECELLID_PREFIX+escapeId(lid)+TABLECELLID_POSTFIX;
				tableCellParentId = objData.parent === "#" ? null : objData.parent;
				a.addClass(c);
				//renderAWidth(a,_this);
				renderATitle(a,t,_this);
				last = a;
				// find which column our tree shuld go in
				var s = this.settings.table;
				var treecol = 0;
				for (i=0;i<s.columns.length;i++) {
					if (s.columns[i].tree) {
						// save which column it was
						treecol = i;
						// do not check any others
						break;
					}
				}
				for (i=0;i<cols.length;i++) {
					if (treecol === i) {
						continue;
					}
					col = cols[i];
					dataCell = mw.children("div:eq("+i+")");
					// get the cellClass, the wideCellClass, and the columnClass
					cl = col.cellClass || "";
					wcl = col.wideCellClass || "";
					ccl = col.columnClass || "";

					// add a column class to the dataCell
					dataCell.addClass(ccl);

					// get the contents of the cell
					val = "";
					if (objData.data && objData.data[col.value] !== undefined) {
						val = objData.data[col.value];
					}

					if (typeof(col.format) === "function") {
						val = col.format(val);
					}

					// put images instead of text if needed
					if (col.images) {
					img = col.images[val] || col.images["default"];
					if (img) {content = img[0] === "*" ? '<span class="'+img.substr(1)+'"></span>' : '<img src="'+img+'">';}
					} else { content = val; }

					// content cannot be blank, or it messes up heights
					if (content === undefined || content === null || BLANKRE.test(content)) {
						content = "&nbsp;";
					}

					// get the valueClass
					valClass = col.valueClass && objData.data !== null && objData.data !== undefined ? objData.data[col.valueClass] || "" : "";
					if (valClass && col.valueClassPrefix && col.valueClassPrefix !== "") {
						valClass = col.valueClassPrefix + valClass;
					}
					// get the wideValueClass
					wideValClass = col.wideValueClass && objData.data !== null && objData.data !== undefined ? objData.data[col.wideValueClass] || "" : "";
					if (wideValClass && col.wideValueClassPrefix && col.wideValueClassPrefix !== "") {
						wideValClass = col.wideValueClassPrefix + wideValClass;
					}
					// get the title
					title = col.title && objData.data !== null && objData.data !== undefined ? objData.data[col.title] || "" : "";
					// strip out HTML
					if (typeof title === 'string') {
						title = title.replace(htmlstripre, '');
					}

					// get the width
					paddingleft = 7;
					width = col.width || defaultWidth;
					if (width !== 'auto') {
						width = tmpWidth || (width - paddingleft);
					}

					last = findDataCell(dataCell, lid);
					if (!last || last.length < 1) {
						last = $("<div></div>");
						$("<span></span>").appendTo(last);
						last.attr("id",tableCellName+i);
						last.addClass(tableCellName);
						last.attr(NODE_DATA_ATTR,lid);

					}
					// we need to put it in the dataCell - after the parent, but the position matters
					// if we have no parent, then we are one of the root nodes, but still need to look at peers


					// if we are first, i.e. pos === 0, we go right after the parent;
					// if we are not first, and our previous peer (one before us) is closed, we go right after the previous peer cell
					// if we are not first, and our previous peer is opened, then we have to find its youngest & lowest closed child (incl. leaf)
					//
					// probably be much easier to go *before* our next one
					// but that one might not be drawn yet
					// here is the logic for jstree drawing:
					//   it draws peers from first to last or from last to first
					//   it draws children before a parent
					//
					// so I can rely on my *parent* not being drawn, but I cannot rely on my previous peer or my next peer being drawn

					// so we do the following:
					//   1- We are the first child: install after the parent
					//   2- Our previous peer is already drawn: install after the previous peer
					//   3- Our previous peer is not drawn, we have a child that is drawn: install right before our first child
					//   4- Our previous peer is not drawn, we have no child that is drawn, our next peer is drawn: install right before our next peer
					//   5- Our previous peer is not drawn, we have no child that is drawn, our next peer is not drawn: install right after parent
					tableCellPrevId = pos <=0 ? objData.parent : findLastClosedNode(this,peers[pos-1]);
					tableCellPrev = findDataCell(dataCell,tableCellPrevId);
					tableCellNextId = pos >= peers.length-1 ? "NULL" : peers[pos+1];
					tableCellNext = findDataCell(dataCell,tableCellNextId);
					tableCellChildId = objData.children && objData.children.length > 0 ? objData.children[0] : "NULL";
					tableCellChild = findDataCell(dataCell,tableCellChildId);
					tableCellParent = findDataCell(dataCell,tableCellParentId);

					// if our parent is already drawn, then we put this in the right order under our parent
					if (tableCellParentId) {
						if (tableCellParent && tableCellParent.length > 0) {
							if (tableCellPrev && tableCellPrev.length > 0) {
								last.insertAfter(tableCellPrev);
							} else if (tableCellChild && tableCellChild.length > 0) {
								last.insertBefore(tableCellChild);
							} else if (tableCellNext && tableCellNext.length > 0) {
								last.insertBefore(tableCellNext);
							} else {
								last.insertAfter(tableCellParent);
							}
							rendered = true;
						} else {
							rendered = false;
						}
						// always put it in the holding cells, and then sort when the parent comes in, in case parent is (re)drawn later
						hc[tableCellName+i] = last;
					} else {
						if (tableCellPrev && tableCellPrev.length > 0) {
							last.insertAfter(tableCellPrev);
						} else if (tableCellChild && tableCellChild.length > 0) {
							last.insertBefore(tableCellChild);
						} else if (tableCellNext && tableCellNext.length > 0) {
							last.insertBefore(tableCellNext);
						} else {
							last.appendTo(dataCell);
						}
						rendered = true;
					}
					// do we have any children waiting for this cell? walk down through the children/grandchildren/etc tree
					if (rendered) {
						last.after(this.getHoldingCells(objData,i,hc));
					}
					// need to make the height of this match the line height of the tree. How?
					span = last.children("span");

					// create a span inside the div, so we can control what happens in the whole div versus inside just the text/background
					span.addClass(cl+" "+valClass).html(content);
					last = last.css(conf).addClass("jstree-table-cell jstree-table-cell-regular jstree-table-cell-root-"+rootid+" jstree-table-cell-"+classAdd+" "+wcl+ " " + wideValClass + (tr?" ui-state-default":"")).addClass("jstree-table-col-"+i);
					// add click handler for clicking inside a table cell
					last.click(cellClickHandler(tree,t,val,col,this));
					last.dblclick(cellDblClickHandler(tree,t,val,col,this));
					last.on("contextmenu",cellRightClickHandler(tree,t,val,col,this));
					last.hover(hoverInHandler(t, this), hoverOutHandler(t, this));

					if (title) {
						span.attr("title",title);
					}
				}
				last.addClass("jstree-table-cell-last"+(tr?" ui-state-default":""));
				// if there is no width given for the last column, do it via automatic
				if (cols[cols.length-1].width === undefined) {
					last.addClass("jstree-table-width-auto").next(".jstree-table-separator").remove();
				}
			}
			this.element.css({'overflow-y':'auto !important'});
		};
		// clean up holding cells
		this.holdingCells = {};
	};
}));
