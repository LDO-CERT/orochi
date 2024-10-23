(function() {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['dump_folder'] = template({"1":function(container,depth0,helpers,partials,data) {
    var stack1, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return " "
    + container.escapeExpression(container.lambda(((stack1 = (depth0 != null ? lookupProperty(depth0,"foler") : depth0)) != null ? lookupProperty(stack1,"name") : stack1), depth0))
    + " ";
},"3":function(container,depth0,helpers,partials,data) {
    return " - ";
},"5":function(container,depth0,helpers,partials,data) {
    return "                <i class=\"fab fa-linux me-1\"></i>\n";
},"7":function(container,depth0,helpers,partials,data) {
    return "                <i class=\"fab fa-windows me-1\"></i>\n";
},"9":function(container,depth0,helpers,partials,data) {
    return "                <i class=\"fab fa-apple me-1\"></i>\n";
},"11":function(container,depth0,helpers,partials,data) {
    return "                <i class=\"fas fa-robot me-1\"></i>\n";
},"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {
    var stack1, helper, alias1=depth0 != null ? depth0 : (container.nullContext || {}), alias2=container.escapeExpression, alias3=container.hooks.helperMissing, alias4="function", lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return "<ul class=\"nav flex-column\" id=\"index-list\">\n    <li class=\"nav-item ms-2\"><i class=\"fa-regular fa-folder\"></i>\n    "
    + ((stack1 = lookupProperty(helpers,"if").call(alias1,(depth0 != null ? lookupProperty(depth0,"folder") : depth0),{"name":"if","hash":{},"fn":container.program(1, data, 0),"inverse":container.program(3, data, 0),"data":data,"loc":{"start":{"line":3,"column":4},"end":{"line":3,"column":53}}})) != null ? stack1 : "")
    + "\n    </li>\n    <ul class=\"list-group list-group-flush nested-list\" id=\"folder_"
    + alias2(container.lambda(((stack1 = (depth0 != null ? lookupProperty(depth0,"folder") : depth0)) != null ? lookupProperty(stack1,"name") : stack1), depth0))
    + "\">\n        <li class=\"list-group-item\">\n            <label class=\"check_container\" data-index=\""
    + alias2(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":7,"column":55},"end":{"line":7,"column":64}}}) : helper)))
    + "\" data-color=\""
    + alias2(((helper = (helper = lookupProperty(helpers,"color") || (depth0 != null ? lookupProperty(depth0,"color") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"color","hash":{},"data":data,"loc":{"start":{"line":7,"column":78},"end":{"line":7,"column":87}}}) : helper)))
    + "\">\n"
    + ((stack1 = (lookupProperty(helpers,"ifeq")||(depth0 && lookupProperty(depth0,"ifeq"))||alias3).call(alias1,(depth0 != null ? lookupProperty(depth0,"operating_system") : depth0),"Linux",{"name":"ifeq","hash":{},"fn":container.program(5, data, 0),"inverse":container.noop,"data":data,"loc":{"start":{"line":8,"column":16},"end":{"line":10,"column":25}}})) != null ? stack1 : "")
    + ((stack1 = (lookupProperty(helpers,"ifeq")||(depth0 && lookupProperty(depth0,"ifeq"))||alias3).call(alias1,(depth0 != null ? lookupProperty(depth0,"operating_system") : depth0),"Windows",{"name":"ifeq","hash":{},"fn":container.program(7, data, 0),"inverse":container.noop,"data":data,"loc":{"start":{"line":11,"column":16},"end":{"line":13,"column":25}}})) != null ? stack1 : "")
    + ((stack1 = (lookupProperty(helpers,"ifeq")||(depth0 && lookupProperty(depth0,"ifeq"))||alias3).call(alias1,(depth0 != null ? lookupProperty(depth0,"operating_system") : depth0),"Mac",{"name":"ifeq","hash":{},"fn":container.program(9, data, 0),"inverse":container.noop,"data":data,"loc":{"start":{"line":14,"column":16},"end":{"line":16,"column":25}}})) != null ? stack1 : "")
    + ((stack1 = (lookupProperty(helpers,"ifeq")||(depth0 && lookupProperty(depth0,"ifeq"))||alias3).call(alias1,(depth0 != null ? lookupProperty(depth0,"operating_system") : depth0),"Other",{"name":"ifeq","hash":{},"fn":container.program(11, data, 0),"inverse":container.noop,"data":data,"loc":{"start":{"line":17,"column":16},"end":{"line":19,"column":25}}})) != null ? stack1 : "")
    + "\n                <abbr title=\""
    + alias2(((helper = (helper = lookupProperty(helpers,"name") || (depth0 != null ? lookupProperty(depth0,"name") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"name","hash":{},"data":data,"loc":{"start":{"line":21,"column":29},"end":{"line":21,"column":37}}}) : helper)))
    + "\">"
    + alias2(((helper = (helper = lookupProperty(helpers,"name") || (depth0 != null ? lookupProperty(depth0,"name") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"name","hash":{},"data":data,"loc":{"start":{"line":21,"column":39},"end":{"line":21,"column":47}}}) : helper)))
    + "</abbr>\n\n                <input type=\"checkbox\">\n                <span class=\"checkmark\"></span>        \n\n                <div class=\"btn-group float-end\" role=\"group\">\n                    <a href=\"/hex_view/"
    + alias2(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":27,"column":39},"end":{"line":27,"column":48}}}) : helper)))
    + "\" class=\"btn btn-outline-dark hex-index btn-sm\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Hex View\" >\n                        <i class=\"fas fa-asterisk\"></i>\n                    </a>\n                    <button type=\"button\" class=\"btn btn-outline-info info-index btn-sm\" data-index=\""
    + alias2(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":30,"column":101},"end":{"line":30,"column":110}}}) : helper)))
    + "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Dump Info\" >\n                        <i class=\"fas fa-info\"></i>\n                    </button>\n                    <button type=\"button\" class=\"btn btn-outline-danger remove-index btn-sm\" data-index=\""
    + alias2(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":33,"column":105},"end":{"line":33,"column":114}}}) : helper)))
    + "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Delete Dump\" >\n                        <i class=\"fas fa-trash\"></i>\n                    </button>\n                    <button type=\"button\" class=\"btn btn-outline-success edit-index btn-sm\" data-index=\""
    + alias2(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":36,"column":104},"end":{"line":36,"column":113}}}) : helper)))
    + "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Edit Dump\" >\n                        <i class=\"fas fa-edit\"></i>\n                    </button>\n                    <button type=\"button\" class=\"btn btn-outline-warning restart-index btn-sm\" data-index=\""
    + alias2(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":39,"column":107},"end":{"line":39,"column":116}}}) : helper)))
    + "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Restart Auto Plugin\" >\n                        <i class=\"fas fa-backward\"></i>\n                    </button>\n                    <button type=\"button\" class=\"btn btn-outline-dark download_obj download-index btn-sm\" data-path=\"/media/"
    + alias2(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":42,"column":124},"end":{"line":42,"column":133}}}) : helper)))
    + "/linux-sample-1.bin\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Download Dump\" >\n                        <i class=\"fas fa-file-download\"></i>\n                    </button>\n                </div>\n            </label>\n        </li>\n    </ul>\n</ul>\n";
},"useData":true});
})();
