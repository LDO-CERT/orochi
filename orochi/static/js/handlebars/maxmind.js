(function() {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['maxmind'] = template({"1":function(container,depth0,helpers,partials,data) {
    var helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return "    <div class=\"alert alert-danger m-4\" role=\"alert\">\n    "
    + container.escapeExpression(((helper = (helper = lookupProperty(helpers,"errors") || (depth0 != null ? lookupProperty(depth0,"errors") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"errors","hash":{},"data":data,"loc":{"start":{"line":8,"column":4},"end":{"line":8,"column":14}}}) : helper)))
    + "\n    </div>\n";
},"3":function(container,depth0,helpers,partials,data) {
    var stack1, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return "    <div id=\"js_received\" style=\"width: 100%; height: 100%;\"></div>\n    <script>\n        var options = {\n            mode: 'code',\n            modes: ['text', 'code', 'view'],\n            onEditable: function (node) {\n                if (!node.path) { return false; }\n            }\n        }\n        var json_viewer = document.getElementById(\"js_received\")\n        var json_container = new JSONEditor(json_viewer, options)\n        json_container.set("
    + ((stack1 = (lookupProperty(helpers,"json")||(depth0 && lookupProperty(depth0,"json"))||container.hooks.helperMissing).call(depth0 != null ? depth0 : (container.nullContext || {}),(depth0 != null ? lookupProperty(depth0,"info") : depth0),{"name":"json","hash":{},"data":data,"loc":{"start":{"line":22,"column":27},"end":{"line":22,"column":44}}})) != null ? stack1 : "")
    + ")\n    </script>\n";
},"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {
    var stack1, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return "<div class=\"modal-header\">\n    <h5 class=\"modal-title\">Maxmind Report</h5>\n    <button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"modal\" aria-label=\"Close\"></button>\n</div>\n<div class=\"modal-body\">\n"
    + ((stack1 = lookupProperty(helpers,"if").call(depth0 != null ? depth0 : (container.nullContext || {}),(depth0 != null ? lookupProperty(depth0,"errors") : depth0),{"name":"if","hash":{},"fn":container.program(1, data, 0),"inverse":container.program(3, data, 0),"data":data,"loc":{"start":{"line":6,"column":4},"end":{"line":24,"column":11}}})) != null ? stack1 : "")
    + "  </div>\n  <div class=\"modal-footer\">\n    <button type=\"button\" class=\"btn btn-secondary\" data-bs-dismiss=\"modal\">Close</button>\n  </div>\n</form>\n";
},"useData":true});
})();
