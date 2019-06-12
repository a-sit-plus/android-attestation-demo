package com.example.lib

import kotlin.reflect.KProperty1
import kotlin.reflect.full.declaredMemberProperties


fun fancyToString(ob: Any, indentNum: Int): String {
    val indent = " ".repeat(indentNum)
    return "{\n$indent" + ob.javaClass.kotlin.declaredMemberProperties
        .filter(notEmptyOrNull(ob)).joinToString(
            separator = ",\n$indent",
            transform = toKeyValueString(ob)
        ) + "\n$indent}"
}

private fun toKeyValueString(obj: Any): (KProperty1<Any, *>) -> String {
    return {
        it.name + "=" + toString(it.get(obj)!!)
    }
}

private fun notEmptyOrNull(obj: Any): (KProperty1<Any, *>) -> Boolean {
    return {
        when {
            it.get(obj) is Enum<*> -> (it.get(obj) as Enum<*>).name != "NULL"
            it.get(obj) is ByteArray -> (it.get(obj) as ByteArray).isNotEmpty()
            else -> it.get(obj) != null
        }
    }
}

private fun toString(obj: Any): CharSequence {
    return when (obj) {
        is List<*> -> "{" + obj.mapNotNull { toString(it!!) }.joinToString(", ") + "}"
        is ByteArray -> obj.toBase64()
        else -> obj.toString()
    }
}
